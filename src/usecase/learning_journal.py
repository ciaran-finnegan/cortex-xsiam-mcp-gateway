"""Append-only learning journal written by the gateway.

Gateway observers never write fact files. They validate a record, queue it in memory and
return; a background task then appends the queue, off the event loop, to a per-process
JSONL file under ``<TENANT_PACK_DIR>/learned/journal/``. The learner process is the single
writer of the fact files and consumes the journal. Journalling never blocks or fails a tool
call: an error is logged and the record dropped.

Each process writes its own files, named ``<stream>-<UTC date>-<host hash>-<pid>.jsonl``, so
replicas never share a file. Streams: ``events`` (observations, tool steps, fact links,
engagement closes) and ``admin`` (human revert, pin and unpin requests, which read paths
honour before the learner applies them).
"""

import asyncio
import hashlib
import json
import logging
import os
import socket
from datetime import datetime
from pathlib import Path
from typing import Any

from config.config import get_config
from entities.MCPContext import MCPContext
from usecase import learned_store
from usecase.audit import stable_hash
from usecase.learned_store import (
    ADMIN_ACTIONS,
    ENGAGEMENT_KEY_RE,
    ENTRY_ID_RE,
    QUERY_ID_RE,
    TOKEN_RE,
    LearnedFactRefused,
    LearnedStoreError,
    Observation,
    ensure_private_dir,
    get_pack_root,
    is_issued_query_id,
    journal_dir,
    validate_observation,
    write_private_file,
)
from usecase.replay import FACT_KEY_RE

logger = logging.getLogger(__name__)

JOURNAL_VERSION = 1
MAX_RECORD_BYTES = 1024 * 1024
MAX_PENDING_RECORDS = 10_000
MAX_STEP_QUERY_IDS = 50
MAX_ARGUMENT_NAMES = 50
LEARNED_GITIGNORE = "journal/\n.lock\nlearner_state.json\nlearner_spend.json\n"

_pending: list[tuple[str, str]] = []
_flush_task: asyncio.Task | None = None


def reset_state() -> None:
    """Drop queued records. For tests."""
    global _flush_task
    _pending.clear()
    _flush_task = None


def process_tag() -> str:
    host = hashlib.sha256(socket.gethostname().encode()).hexdigest()[:8]
    return f"{host}-{os.getpid()}"


def journal_path(pack_root: Path, stream: str, moment: datetime) -> Path:
    return journal_dir(pack_root) / f"{stream}-{moment:%Y%m%d}-{process_tag()}.jsonl"


def ignore_runtime_files_in_pack_history(root: Path) -> None:
    """Keep the journal, lock and learner state out of the tenant pack's own git history."""
    ignore = root / "learned" / ".gitignore"
    if not ignore.exists() and not ignore.is_symlink():
        write_private_file(ignore, LEARNED_GITIGNORE)


def _principal_block(principal: MCPContext) -> dict[str, Any]:
    return {"id": principal.principal_id, "groups": list(principal.groups)}


def _enqueue(record: dict[str, Any], stream: str = "events", *, even_when_frozen: bool = False) -> bool:
    if not even_when_frozen and not get_config().learning_enabled:
        return False
    try:
        if get_pack_root() is None:
            return False
    except LearnedStoreError as e:
        logger.warning("Learning journal disabled: %s", e)
        return False
    record = {"v": JOURNAL_VERSION, "at": learned_store.iso_timestamp(learned_store.now_utc()), **record}
    line = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    if len(line.encode()) > MAX_RECORD_BYTES:
        logger.info("Learning journal record dropped: larger than %d bytes", MAX_RECORD_BYTES)
        return False
    if len(_pending) >= MAX_PENDING_RECORDS:
        logger.warning("Learning journal queue is full; record dropped")
        return False
    _pending.append((stream, line))
    _schedule_flush()
    return True


def _schedule_flush() -> None:
    global _flush_task
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        _write_batch(_take_pending())
        return
    if _flush_task is None or _flush_task.done():
        _flush_task = loop.create_task(_flush_soon())


def _take_pending() -> list[tuple[str, str]]:
    batch = list(_pending)
    del _pending[: len(batch)]
    return batch


async def _flush_soon() -> None:
    # Yield first so the tool that queued the record returns before any disk work.
    await asyncio.sleep(0)
    await _flush_pending()


async def _flush_pending() -> None:
    while _pending:
        batch = _take_pending()
        try:
            await asyncio.to_thread(_write_batch, batch)
        except Exception as e:
            logger.warning("Learning journal write failed: %s", type(e).__name__)


def _write_batch(batch: list[tuple[str, str]]) -> None:
    if not batch:
        return
    root = get_pack_root()
    if root is None:
        return
    directory = journal_dir(root)
    ensure_private_dir(directory, root)
    ignore_runtime_files_in_pack_history(root)
    grouped: dict[str, list[str]] = {}
    for stream, line in batch:
        grouped.setdefault(stream, []).append(line)
    limit = get_config().learning_journal_max_bytes
    now = learned_store.now_utc()
    for stream, lines in grouped.items():
        payload = ("\n".join(lines) + "\n").encode()
        descriptor = os.open(
            journal_path(root, stream, now),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        try:
            if os.fstat(descriptor).st_size + len(payload) > limit:
                logger.warning("Learning journal file reached LEARNING_JOURNAL_MAX_BYTES; records dropped")
                continue
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
        finally:
            os.close(descriptor)


async def flush() -> None:
    """Wait until every queued record is on disk. For shutdown, the learner and tests."""
    task = _flush_task
    if task is not None and not task.done():
        await task
    await _flush_pending()


# --- Records ---


def journal_observations(
    observations: list[Observation],
    *,
    principal: MCPContext,
    trigger: str,
    engagement: str | None = None,
) -> int:
    """Queue observations whose evidence this process issued. Returns how many were queued. Never raises.

    ``engagement`` is the hashed key of the engagement the observations came from; distinct
    engagements count towards automatic verification.
    """
    queued = 0
    if engagement is not None and not ENGAGEMENT_KEY_RE.match(engagement):
        engagement = None
    for observation in observations:
        try:
            validate_observation(observation, require_issued=True)
        except LearnedFactRefused as e:
            logger.info("Refused learned observation for %s: %s", observation.kind, e)
            continue
        queued += _enqueue(
            {
                "type": "observation",
                "principal": _principal_block(principal),
                "trigger": trigger,
                "kind": observation.kind,
                "dataset": observation.dataset,
                "fact": observation.fact,
                "evidence": list(observation.evidence),
                "source_class": observation.source_class,
                "effect": observation.effect,
                "engagement_key": engagement or observation.engagement,
            }
        )
    return queued


def _bounded_payload(payload: Any) -> Any:
    """Copy a tool result for the replay cache, dropping continuation cursors bound to a live principal."""
    if not isinstance(payload, dict):
        return payload
    cached = dict(payload)
    continuation = cached.get("continuation")
    if isinstance(continuation, dict) and "cursor" in continuation:
        cached["continuation"] = {key: value for key, value in continuation.items() if key != "cursor"}
    return cached


def journal_tool_step(
    *,
    principal: MCPContext,
    engagement_key: str,
    case_id: str | None,
    tool: str,
    started_at: datetime,
    ended_at: datetime,
    duration_ms: float,
    query_ids: list[str],
    units: float | None,
    outcome: str,
    arguments: dict[str, Any] | None,
    payload: Any,
) -> bool:
    """Queue one query-running tool call. The bounded result is kept only when the step belongs to a case."""
    ids = [item for item in query_ids if QUERY_ID_RE.match(item) and is_issued_query_id(item)][:MAX_STEP_QUERY_IDS]
    if not ids or not TOKEN_RE.match(tool):
        return False
    result = None
    cache_note = None
    if case_id is not None and not get_config().learning_result_cache_enabled:
        cache_note = "cache_disabled"
    elif case_id is not None:
        result = _bounded_payload(payload)
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), default=str)
        if len(encoded.encode()) > get_config().learning_result_max_bytes:
            result, cache_note = None, "result_too_large"
    names = sorted(str(name) for name in (arguments or {}) if TOKEN_RE.match(str(name)))[:MAX_ARGUMENT_NAMES]
    return _enqueue(
        {
            "type": "tool_step",
            "principal": _principal_block(principal),
            "engagement_key": engagement_key,
            "case_id": case_id,
            "tool": tool,
            "started_at": learned_store.iso_timestamp(started_at),
            "ended_at": learned_store.iso_timestamp(ended_at),
            "duration_ms": round(duration_ms, 3),
            "query_ids": ids,
            "units": round(units, 6) if isinstance(units, (int, float)) else None,
            "outcome": outcome if outcome in {"success", "error"} else "error",
            "arguments_sha256": stable_hash(arguments or {}),
            "argument_names": names,
            "result": result,
            "cache_note": cache_note,
        }
    )


def journal_fact_link(*, engagement_key: str, case_id: str, key: Any, evidence_query_id: Any) -> bool:
    """Queue a link from an engagement fact key to its evidence query id. Fact values are never copied."""
    if not get_config().learning_result_cache_enabled:
        return False
    if not isinstance(key, str) or not FACT_KEY_RE.match(key):
        return False
    if not isinstance(evidence_query_id, str) or not is_issued_query_id(evidence_query_id):
        return False
    return _enqueue(
        {
            "type": "fact_link",
            "engagement_key": engagement_key,
            "case_id": case_id,
            "key": key,
            "evidence_query_id": evidence_query_id,
        }
    )


def journal_engagement_closed(*, engagement_key: str, case_id: str | None) -> bool:
    """Hook for the engagement module: mark an engagement closed so the learner processes it on its next run."""
    return _enqueue({"type": "engagement_closed", "engagement_key": engagement_key, "case_id": case_id})


async def journal_admin_action(entry_id: str, action: str, *, principal: MCPContext) -> bool:
    """Queue a human revert, pin or unpin and wait until it is on disk. Accepted while learning is frozen."""
    if not isinstance(entry_id, str) or not ENTRY_ID_RE.match(entry_id) or action not in ADMIN_ACTIONS:
        return False
    queued = _enqueue(
        {"type": "admin", "action": action, "entry_id": entry_id, "principal": _principal_block(principal)},
        stream="admin",
        even_when_frozen=True,
    )
    await flush()
    return queued
