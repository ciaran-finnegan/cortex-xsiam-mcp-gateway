"""Bounded engagement result cache and offline replay: the foundation for tier-2 learning.

While an engagement has a case id, the gateway journals each query-running tool call with
the already-bounded result it returned, and the learner writes it to
``<TENANT_PACK_DIR>/engagements/<case_id>/results/``: a manifest of steps (tool, argument
hash, query ids, units, duration, outcome) and one file per result, capped per result and
per case. Successful ``record_fact`` calls add a link from the fact key to its evidence
query id; fact values are not copied.

``replay_engagement`` re-runs the recorded sequence, or a candidate sequence, against
that cache and reports the queries, units and engagement facts it reaches. It never
calls XSIAM, so evaluating a candidate costs no quota. It is a Python function for the
tier-2 approval process, not an MCP tool, so agents cannot read cached results through it.
"""

import importlib
import json
import logging
import re
from functools import lru_cache
from typing import Any

from usecase import learned_store
from usecase.audit import stable_hash
from usecase.learned_store import (
    LearnedStoreError,
    get_pack_root,
    write_private_file,
)

logger = logging.getLogger(__name__)

CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
FACT_KEY_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_CACHED_STEPS = 500
MAX_MANIFEST_FACTS = 500
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_STEP_QUERY_IDS = 50


@lru_cache(maxsize=1)
def _engagement_module():
    try:
        return importlib.import_module("usecase.engagement")
    except ImportError:
        return None


def current_case_id() -> str | None:
    """Case id of the current tool call when the engagement module is installed, else None."""
    engagement = _engagement_module()
    if engagement is None:
        return None
    try:
        scope = engagement.current_scope()
    except Exception:
        return None
    case_id = getattr(scope, "case_id", None)
    return case_id if isinstance(case_id, str) and CASE_ID_RE.match(case_id) else None


def arguments_hash(arguments: dict[str, Any] | None) -> str:
    return stable_hash(arguments or {})


class ResultCache:
    def __init__(self, pack_root):
        self.pack_root = pack_root

    def case_dir(self, case_id: str):
        if not isinstance(case_id, str) or not CASE_ID_RE.match(case_id) or ".." in case_id:
            raise ValueError("case_id must be a short identifier")
        directory = self.pack_root / "engagements" / case_id / "results"
        if not directory.resolve(strict=False).is_relative_to(self.pack_root):
            raise LearnedStoreError("Case path escapes TENANT_PACK_DIR")
        return directory

    def load_manifest(self, case_id: str) -> dict[str, Any]:
        path = self.case_dir(case_id) / "manifest.json"
        empty = {"version": 1, "case_id": case_id, "bytes": 0, "steps": [], "facts": []}
        if path.is_symlink():
            raise LearnedStoreError("Result manifest must not be a symbolic link")
        if not path.exists():
            return empty
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise LearnedStoreError("Result manifest exceeds the size limit")
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise LearnedStoreError("Result manifest is unreadable") from e
        if not isinstance(manifest, dict) or manifest.get("case_id") != case_id:
            raise LearnedStoreError("Result manifest does not match its case")
        manifest.setdefault("steps", [])
        manifest.setdefault("facts", [])
        manifest.setdefault("bytes", 0)
        return manifest

    def save_manifest(self, case_id: str, manifest: dict[str, Any]) -> None:
        manifest["updated_at"] = learned_store.iso_timestamp(learned_store.now_utc())
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        if len(payload.encode()) > MAX_MANIFEST_BYTES:
            raise LearnedStoreError("Result manifest would exceed the size limit")
        write_private_file(self.case_dir(case_id) / "manifest.json", payload)

    def result_path(self, case_id: str, result_file: str):
        if not re.fullmatch(r"\d{4}\.json", result_file or ""):
            raise LearnedStoreError("Invalid result file name")
        return self.case_dir(case_id) / result_file


def get_result_cache() -> ResultCache | None:
    root = get_pack_root()
    return ResultCache(root) if root is not None else None


def ignore_results_in_pack_history(pack_root) -> None:
    """Keep cached tenant results out of the tenant pack's own git history."""
    ignore = pack_root / "engagements" / ".gitignore"
    if not ignore.exists() and not ignore.is_symlink():
        write_private_file(ignore, "*/results/\n")


def _candidate_key(item: Any) -> tuple[str, str]:
    if not isinstance(item, dict) or not isinstance(item.get("tool"), str):
        raise ValueError("Each candidate step needs a tool and arguments or arguments_sha256")
    if "arguments_sha256" in item:
        digest = item["arguments_sha256"]
        if not isinstance(digest, str) or not HASH_RE.match(digest):
            raise ValueError("arguments_sha256 must be a sha256 digest")
        return item["tool"], digest
    arguments = item.get("arguments")
    if arguments is not None and not isinstance(arguments, dict):
        raise ValueError("Candidate arguments must be an object")
    return item["tool"], arguments_hash(arguments)


def _replay(cache: ResultCache, case_id: str, manifest: dict[str, Any], sequence: list[tuple[str, str]]) -> dict[str, Any]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for step in manifest["steps"]:
        key = (step["tool"], step["arguments_sha256"])
        if key not in index or (index[key]["result_file"] is None and step["result_file"]):
            index[key] = step
    reached: set[str] = set()
    queries = 0
    units = 0.0
    steps_without_units = 0
    detail = []
    misses = []
    for position, (tool, digest) in enumerate(sequence):
        step = index.get((tool, digest))
        hit = bool(step and step["result_file"] and cache.result_path(case_id, step["result_file"]).is_file())
        if hit:
            reached.update(step["query_ids"])
            queries += len(step["query_ids"])
            if step["units"] is None:
                steps_without_units += 1
            else:
                units += step["units"]
        else:
            misses.append({"position": position, "tool": tool, "arguments_sha256": digest})
        detail.append(
            {
                "position": position,
                "tool": tool,
                "hit": hit,
                "query_ids": list(step["query_ids"]) if hit else [],
                "units": step["units"] if hit else None,
            }
        )
    facts = manifest["facts"]
    facts_reached = sorted({fact["key"] for fact in facts if fact["evidence_query_id"] in reached})
    all_keys = sorted({fact["key"] for fact in facts})
    return {
        "steps": len(sequence),
        "cache_hits": len(sequence) - len(misses),
        "cache_misses": len(misses),
        "queries": queries,
        "distinct_query_ids": len(reached),
        "units": round(units, 6),
        "steps_without_units": steps_without_units,
        "facts_total": len(all_keys),
        "facts_reached": facts_reached,
        "facts_missed": [key for key in all_keys if key not in facts_reached],
        "misses": misses,
        "detail": detail,
    }


def replay_engagement(case_id: str, candidate: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Re-run a recorded engagement, or a candidate sequence, against the result cache.

    A candidate is a list of ``{"tool": ..., "arguments": {...}}`` or
    ``{"tool": ..., "arguments_sha256": ...}`` steps. A step that was never recorded is a
    cache miss: a live run would need quota for it, so its units are unknown. Replay
    spends no quota (``quota_units_spent`` is always 0).
    """
    cache = get_result_cache()
    if cache is None:
        raise LearnedStoreError("TENANT_PACK_DIR is not configured")
    manifest = cache.load_manifest(case_id)
    if not manifest["steps"]:
        raise ValueError(f"No recorded engagement for case {case_id}")
    recorded = [(step["tool"], step["arguments_sha256"]) for step in manifest["steps"]]
    baseline = _replay(cache, case_id, manifest, recorded)
    report: dict[str, Any] = {
        "case_id": case_id,
        "sequence": "recorded" if candidate is None else "candidate",
        "quota_units_spent": 0,
        "recorded_steps": len(recorded),
    }
    if candidate is None:
        report.update(baseline)
        return report
    if not isinstance(candidate, list) or not candidate or len(candidate) > MAX_CACHED_STEPS:
        raise ValueError("candidate must be a non-empty list of steps")
    report.update(_replay(cache, case_id, manifest, [_candidate_key(item) for item in candidate]))
    report["baseline"] = {
        key: baseline[key] for key in ("steps", "queries", "units", "facts_reached", "cache_misses")
    }
    return report
