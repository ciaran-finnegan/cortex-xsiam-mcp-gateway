"""The ``sessions`` stage: read the XQL query history and group it into sessions. No model is involved.

It reads ``xql_query_center_history`` through the backfill's query path, as the learner principal,
so dataset policy, tool policy, audit, the reserve and a per-invocation unit budget all apply.
Unlike the backfill it selects ``issuer``, because a session is one person's queries close together
in time. The issuer is reduced to a keyed hash and a kind on arrival and never stored raw. Query
text is tokenised on arrival too (``intents.literals``), so raw literals never reach a file.

Progress is committed one day at a time, so a run that stops is resumed by the same command.
"""

import hashlib
import hmac
import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from config.config import get_config
from intents import store as intents_store
from intents.literals import tokenise_query
from intents.settings import IntentSettingsError, kept_literals, load_settings
from usecase import learned_store, learning_journal
from usecase.audit import create_learning_audit_event, emit_audit_event
from usecase.identity import service_principal
from usecase.learned_store import (
    IDENTIFIER_RE,
    QUERY_ID_RE,
    TOKEN_RE,
    get_learned_store,
    iso_timestamp,
)
from usecase.learner import (
    BACKFILL_LOCK_WAIT_SECONDS,
    BACKFILL_MAX_DAYS,
    BACKFILL_MAX_UNITS,
    DAY_MS,
    HISTORY_DATASET,
    HISTORY_FAILED_STATUS,
    LearnerContext,
    _add_spend,
    _backfill_slice,
    _BackfillRun,
    _finite,
    _validation_message,
    learner_principal,
)
from usecase.learning_observers import (
    classify_xql_failure,
    parse_xql,
    window_bucket,
    window_ms,
)
from usecase.log_policy import authorize_dataset
from usecase.tool_policy import authorize_tool
from usecase.xql_results import TRUNCATION_MARKER

logger = logging.getLogger(__name__)

HISTORY_FIELDS = [
    "_time",
    "execution_id",
    "issuer",
    "status",
    "status_details",
    "compute_units",
    "execution_duration_secs",
    "result_count",
    "timeframe_duration_secs",
    "xql_query_source",
    "query_tables",
    "xql_query",
]
AUTOMATED_SOURCES = frozenset({"correlation", "dashboard", "playbook", "widget"})
OUTCOMES = ("abandoned_after_failure", "ended_in_rows", "ended_with_no_rows", "no_readable_steps", "unknown")
MAX_STEP_DATASETS = 20
_FAILURE_BY_STATUS = {HISTORY_FAILED_STATUS: "other", "STATUS_100_CANCELLED": "cancelled", "STATUS_120_TIMEOUT": "timeout"}
_STATUS_RE = re.compile(r"^STATUS_[0-9]{3}_[A-Z_]{1,40}$")


def _progress_path(root: Path) -> Path:
    return intents_store.intents_dir(root) / "history.json"


def sessions_path(root: Path) -> Path:
    return intents_store.intents_dir(root) / "sessions.json"


def _issuer_kind(issuer: str) -> str:
    if "@" in issuer:
        return "person"
    return "api_key" if issuer.lower().startswith("public api") else "other"


def _tables(value: Any) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            value = [value]
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and IDENTIFIER_RE.match(item)]


def build_step(row: dict[str, Any], key: bytes, keep: frozenset[str]) -> tuple[dict[str, Any] | None, str | None]:
    """One history row as one stored step, or the reason it gave none.

    The raw issuer, the raw query text and the validation message stop here. ``status_details``
    also holds a tenant-id key, so only its validation message is read, and only to classify it.
    """
    issuer, execution_id, query = row.get("issuer"), row.get("execution_id"), row.get("xql_query")
    if not isinstance(issuer, str) or not issuer.strip():
        return None, "no_issuer"
    issuer = issuer.strip()
    if issuer.lower() == "system":
        return None, "system_issuer"
    if not isinstance(execution_id, str) or not QUERY_ID_RE.match(execution_id) or not isinstance(query, str):
        return None, "invalid_row"
    step: dict[str, Any] = {
        "execution_id": execution_id,
        "at_ms": int(row["_time"]),
        "issuer_hmac": hmac.new(key, issuer.lower().encode(), hashlib.sha256).hexdigest(),
        "issuer_kind": _issuer_kind(issuer),
    }
    if query.endswith(TRUNCATION_MARKER):
        return {**step, "truncated": True}, None
    tokenised = tokenise_query(query, keep)
    status = row.get("status") if isinstance(row.get("status"), str) and _STATUS_RE.match(row["status"]) else "other"
    failure_class = _FAILURE_BY_STATUS.get(status)
    unknown_field = None
    if status == HISTORY_FAILED_STATUS:
        classified = classify_xql_failure(_validation_message(row.get("status_details")), query)
        if classified is not None:
            failure_class = classified["error_class"]
            # An unquoted value is reported as an unknown field, so the name must have survived tokenising.
            name = classified["unknown_field"]
            unknown_field = name if name in tokenised.fields else None
    source = row.get("xql_query_source")
    seconds = _finite(row.get("timeframe_duration_secs"))
    timeframe = {"relativeTime": int(seconds * 1000)} if seconds is not None else None
    results = _finite(row.get("result_count"))
    return {
        **step,
        "truncated": False,
        "source": source.lower() if isinstance(source, str) and TOKEN_RE.match(source) else "other",
        "status": status,
        "datasets": list(dict.fromkeys([*tokenised.datasets, *_tables(row.get("query_tables"))]))[:MAX_STEP_DATASETS],
        "query": tokenised.text,
        "fields": list(tokenised.fields),
        "literals": tokenised.literals,
        "result_count": int(results) if results is not None else None,
        "compute_units": _finite(row.get("compute_units")),
        "duration_secs": _finite(row.get("execution_duration_secs")),
        "window": window_bucket(window_ms(timeframe, parse_xql(query))),
        "failure_class": failure_class,
        "unknown_field": unknown_field,
    }, None


def outcome_signals(steps: list[dict[str, Any]]) -> dict[str, Any]:
    """What the session measurably did, with no model involved. Steps are in time order."""
    last = steps[-1] if steps else None
    if last is None:
        outcome = "no_readable_steps"
    elif last["failure_class"]:
        outcome = "abandoned_after_failure"
    elif last["result_count"] is None:
        outcome = "unknown"
    else:
        outcome = "ended_in_rows" if last["result_count"] > 0 else "ended_with_no_rows"
    first_failure = next((index for index, step in enumerate(steps) if step["failure_class"]), None)
    datasets = [step["datasets"][0] if step["datasets"] else None for step in steps]
    return {
        "outcome": outcome,
        "failed_steps": sum(1 for step in steps if step["failure_class"]),
        "empty_steps": sum(1 for step in steps if step["result_count"] == 0),
        "recovered_after_failure": first_failure is not None
        and any((step["result_count"] or 0) > 0 and not step["failure_class"] for step in steps[first_failure + 1 :]),
        "dataset_switches": sum(1 for before, after in zip(datasets, datasets[1:], strict=False) if before != after),
        "automated_only": bool(steps) and all(step["source"] in AUTOMATED_SOURCES for step in steps),
        "dead_ends": [
            {"dataset": step["datasets"][0] if step["datasets"] else None, "field": step["unknown_field"]}
            for step in steps
            if step["unknown_field"]
        ],
    }


def _session(issuer_hmac: str, members: list[dict[str, Any]]) -> dict[str, Any]:
    execution_ids = [step["execution_id"] for step in members]
    steps = []
    previous_ms = None
    for member in members:
        if not member["truncated"]:
            gap = None if previous_ms is None else round((member["at_ms"] - previous_ms) / 1000)
            steps.append(
                {key: value for key, value in member.items() if key not in {"issuer_hmac", "issuer_kind", "truncated"}}
                | {"gap_seconds": gap}
            )
            previous_ms = member["at_ms"]
    return {
        # From the execution ids, so the same session has the same id in another pack.
        "session_id": hashlib.sha256("\n".join(execution_ids).encode()).hexdigest()[:24],
        "issuer_hmac": issuer_hmac,
        "issuer_kind": members[0]["issuer_kind"],
        "started_ms": members[0]["at_ms"],
        "ended_ms": members[-1]["at_ms"],
        "execution_ids": execution_ids,
        "truncated_steps": len(members) - len(steps),
        "steps": steps,
        "signals": outcome_signals(steps),
    }


def group_sessions(steps: list[dict[str, Any]], gap_ms: int) -> list[dict[str, Any]]:
    """The same issuer's steps, split wherever the time between two of them is longer than the gap."""
    by_issuer: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for step in steps:
        by_issuer[step["issuer_hmac"]].setdefault(step["execution_id"], step)
    sessions = []
    for issuer_hmac, members in by_issuer.items():
        current: list[dict[str, Any]] = []
        for step in sorted(members.values(), key=lambda item: (item["at_ms"], item["execution_id"])):
            if current and step["at_ms"] - current[-1]["at_ms"] > gap_ms:
                sessions.append(_session(issuer_hmac, current))
                current = []
            current.append(step)
        if current:
            sessions.append(_session(issuer_hmac, current))
    return sorted(sessions, key=lambda session: (session["started_ms"], session["session_id"]))


def _write_sessions(root: Path, progress: dict[str, Any], gap_minutes: int, now: datetime) -> list[dict[str, Any]]:
    sessions = group_sessions(progress["steps"], gap_minutes * 60_000)
    dead_ends: Counter = Counter()
    for session in sessions:
        for pair in {(item["dataset"], item["field"]) for item in session["signals"]["dead_ends"]}:
            dead_ends[pair] += 1
    intents_store.write_json(
        sessions_path(root),
        {
            "generated_at": iso_timestamp(now),
            "complete": progress["completed_at"] is not None,
            "from_ms": progress["from_ms"],
            "to_ms": progress["to_ms"],
            "gap_minutes": gap_minutes,
            "keep_literals": progress["keep_literals"],
            "dead_ends": [
                {"dataset": dataset, "field": name, "sessions": count} for (dataset, name), count in dead_ends.most_common()
            ],
            "sessions": sessions,
        },
    )
    return sessions


def _skipped(reason: str, **details: Any) -> dict[str, Any]:
    return {"command": "sessions", "skipped": reason, **details}


async def run_sessions(days: int, max_units: float, *, now: datetime | None = None) -> dict[str, Any]:
    """Read the history into tokenised steps and write ``sessions.json``. Run by an operator.

    The range is fixed by the first run. To read a different range, an operator deletes
    ``intents/history.json`` and ``intents/sessions.json``.
    """
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= BACKFILL_MAX_DAYS:
        raise ValueError(f"days must be between 1 and {BACKFILL_MAX_DAYS}")
    if not 0 < max_units <= BACKFILL_MAX_UNITS:
        raise ValueError(f"max_units must be above 0 and at most {BACKFILL_MAX_UNITS:g}")
    config = get_config()
    store = get_learned_store()
    if not config.learning_enabled:
        logger.info("Learning is frozen (LEARNING_ENABLED=false); the sessions stage did nothing")
        return _skipped("learning_disabled")
    if store is None:
        return _skipped("no_tenant_pack")
    try:
        settings = load_settings()
        keep = kept_literals(settings)
    except IntentSettingsError as e:
        return {"command": "sessions", "refused": "invalid_settings", "settings": e.settings}
    principal = learner_principal()
    if not authorize_tool(principal, "query_dataset").allowed or not authorize_dataset(principal, HISTORY_DATASET).allowed:
        return _skipped("not_authorized")
    now = now or learned_store.now_utc()
    root = store.pack_root
    path = _progress_path(root)
    async with store.locked(wait_seconds=BACKFILL_LOCK_WAIT_SECONDS):
        learning_journal.ignore_runtime_files_in_pack_history(root)
        intents_store.prepare(root)
        key = intents_store.issuer_key(root)
        progress = intents_store.read_json(path)
        if progress is None:
            to_ms = int(now.timestamp() * 1000)
            from_ms = to_ms - days * DAY_MS
            progress = {
                "from_ms": from_ms,
                "to_ms": to_ms,
                "next_ms": from_ms,
                "started_at": iso_timestamp(now),
                "completed_at": None,
                "queries": 0,
                "units_at_most": 0.0,
                "keep_literals": sorted(keep),
                "skipped_rows": {},
                "steps": [],
            }
            intents_store.write_json(path, progress)
        elif progress["completed_at"] is not None:
            return _skipped("already_completed", steps=len(progress["steps"]))
        elif progress["keep_literals"] != sorted(keep):
            # Stored steps are already tokenised, so one run cannot mix two settings.
            return {"command": "sessions", "refused": "keep_literals_changed"}
    run = _BackfillRun(
        ctx=LearnerContext(principal),
        principal=principal,
        max_units=max_units,
        limit=config.dataset_query_max_rows,
        fields=HISTORY_FIELDS,
    )
    max_span = config.dataset_query_max_timeframe_ms
    slice_ms = min(DAY_MS, max_span) if max_span > 0 else DAY_MS
    stopped = None
    with service_principal(principal):
        while stopped is None and progress["next_ms"] < progress["to_ms"]:
            start = progress["next_ms"]
            end = min(start + slice_ms, progress["to_ms"])
            rows, stopped = await _backfill_slice(run, start, end)
            async with store.locked(wait_seconds=BACKFILL_LOCK_WAIT_SECONDS):
                progress = intents_store.read_json(path)
                new_steps = 0
                if progress["next_ms"] != start:
                    stopped = "concurrent_run"
                elif stopped is None:
                    for row in rows:
                        step, reason = build_step(row, key, keep)
                        if step is None:
                            progress["skipped_rows"][reason] = progress["skipped_rows"].get(reason, 0) + 1
                        else:
                            progress["steps"].append(step)
                            new_steps += 1
                    progress["next_ms"] = end
                    if end >= progress["to_ms"]:
                        progress["completed_at"] = iso_timestamp(now)
                spent = round(run.spent - run.saved_spent, 6)
                progress["queries"] += run.queries - run.saved_queries
                progress["units_at_most"] = round(progress["units_at_most"] + spent, 6)
                await emit_audit_event(
                    create_learning_audit_event(
                        operation="intents_sessions",
                        principal=principal,
                        changes=[],
                        trigger="intents",
                        details={"slice": {"from_ms": start, "to_ms": end}, "rows": len(rows), "steps": new_steps},
                    )
                )
                _add_spend(root, now.date().isoformat(), spent)
                intents_store.write_json(path, progress)
                run.saved_queries, run.saved_spent = run.queries, run.spent
    sessions = _write_sessions(root, progress, settings.session_gap_minutes, now)
    report = {
        "command": "sessions",
        "at": iso_timestamp(now),
        "stopped": stopped,
        "complete": progress["completed_at"] is not None,
        "this_run": {"queries": run.queries, "units_at_most": run.spent},
        "full_windows": run.full_windows,
        "invalid_rows": run.invalid_rows,
        "progress": {
            key_name: progress[key_name]
            for key_name in ("from_ms", "to_ms", "next_ms", "queries", "units_at_most", "skipped_rows", "keep_literals")
        },
        "steps": len(progress["steps"]),
        "truncated_steps": sum(session["truncated_steps"] for session in sessions),
        "sessions": len(sessions),
        "outcomes": dict(Counter(session["signals"]["outcome"] for session in sessions)),
    }
    await emit_audit_event(
        create_learning_audit_event(
            operation="intents_sessions", principal=principal, changes=[], trigger="intents", details=report
        )
    )
    await learning_journal.flush()
    return report
