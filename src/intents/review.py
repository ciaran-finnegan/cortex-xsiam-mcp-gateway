"""The ``review`` stage: a spreadsheet a person marks up, and the precision that follows from it.

Replay cannot score these labels, because old queries have no cached results, so a person judges
them. The file is rewritten on every run, keeping what the reviewer entered, and the report counts it.

The file holds attacker-writable text and is meant for a spreadsheet program, so a cell that would
run as a formula is neutralised.
"""

import csv
import io
from collections import Counter
from pathlib import Path
from typing import Any

from config.config import get_config
from intents import store as intents_store
from intents.labels import (
    CONTENT_TRUST,
    MAX_PROMPT_STEPS,
    load_labels,
    load_sessions,
    session_payload,
)
from usecase.learned_store import get_learned_store, write_private_file

VERDICTS = ("right", "wrong", "unsure")
MAX_CELL_CHARS = 32_000  # spreadsheet programs cut a cell at 32,767
REVIEWER_COLUMNS = ("verdict", "correct_intent", "tokens_hid_intent", "notes")
LABEL_COLUMNS = (
    "intent",
    "confidence",
    "model_says_tokens_hid_intent",
    "summary_inferred",
    "outcome",
    "steps",
    "steps_not_sent",
    "failed_steps",
    "term_tokens",
    "datasets",
    "fields",
    "queries_as_sent",
    "execution_ids",
)
COLUMNS = ("session_id", *REVIEWER_COLUMNS, *LABEL_COLUMNS)


def review_path(root: Path) -> Path:
    return intents_store.intents_dir(root) / "review.csv"


def _safe_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text[:MAX_CELL_CHARS]
    return f"'{text}" if text[:1] in {"=", "+", "-", "@", "\t", "\r"} else text


def _queries_as_sent(payload: dict[str, Any]) -> str:
    """The prompt's own steps, so a reviewer judges a label on what the model received."""
    lines = []
    for number, step in enumerate(payload["steps"], start=1):
        failure = f" [{step['failure_class']}]" if step["failure_class"] else ""
        lines.append(f"{number}. rows={step['result_count']}{failure} {step['query']}")
    if payload["steps_omitted_from_the_middle"]:
        lines.insert(MAX_PROMPT_STEPS // 2, f"({payload['steps_omitted_from_the_middle']} steps not sent here)")
    return "\n".join(lines)


def _term_tokens(session: dict[str, Any]) -> int:
    return sum(step["literals"].get("term", 0) for step in session["steps"])


def _row(session: dict[str, Any], label: dict[str, Any], entered: dict[str, str]) -> dict[str, str]:
    payload = session_payload(session)
    values = {
        "session_id": session["session_id"],
        **{column: entered.get(column, "") for column in REVIEWER_COLUMNS},
        "intent": label["intent"],
        "confidence": label["confidence"],
        "model_says_tokens_hid_intent": "yes" if label["tokens_hid_intent"] else "no",
        "summary_inferred": label["summary"],
        "outcome": session["signals"]["outcome"],
        "steps": len(session["steps"]),
        "steps_not_sent": payload["steps_omitted_from_the_middle"] + payload["steps_omitted_as_too_long"],
        "failed_steps": session["signals"]["failed_steps"],
        "term_tokens": _term_tokens(session),
        "datasets": ", ".join(label["datasets"]),
        "fields": ", ".join(label["fields"]),
        "queries_as_sent": _queries_as_sent(payload),
        "execution_ids": " ".join(session["execution_ids"]),
    }
    return {column: _safe_cell(value) for column, value in values.items()}


def _read_entered(path: Path) -> dict[str, dict[str, str]]:
    if not intents_store.check_readable(path):
        return {}
    # utf-8-sig because spreadsheet programs save a byte order mark.
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return {
            row["session_id"]: {column: row.get(column) or "" for column in REVIEWER_COLUMNS}
            for row in csv.DictReader(handle)
            if row.get("session_id")
        }


def _precision(counts: Counter) -> float | None:
    judged = counts["right"] + counts["wrong"]
    return round(counts["right"] / judged, 3) if judged else None


def _bucket(counts: Counter) -> dict[str, Any]:
    return {"right": counts["right"], "wrong": counts["wrong"], "precision": _precision(counts)}


def run_review() -> dict[str, Any]:
    """Write ``intents/review.csv`` and report what the reviewer has marked so far."""
    config = get_config()
    store = get_learned_store()
    if not config.learning_enabled:
        return {"command": "review", "skipped": "learning_disabled"}
    if store is None:
        return {"command": "review", "skipped": "no_tenant_pack"}
    root = store.pack_root
    stored = load_sessions(root)
    if stored is None:
        return {"command": "review", "refused": "no_sessions"}
    intents_store.prepare(root)
    labels = load_labels(root)
    path = review_path(root)
    entered = _read_entered(path)
    verdicts: Counter = Counter()
    by_intent: dict[str, Counter] = {}
    by_terms = {"with_term_tokens": Counter(), "without_term_tokens": Counter()}
    reviewer_says_hidden: Counter = Counter()
    model_says_hidden = 0
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS)
    writer.writeheader()
    for session in stored["sessions"]:
        label = labels.get(session["session_id"])
        if label is None or label["status"] != "labelled":
            continue
        marks = entered.get(session["session_id"], {})
        writer.writerow(_row(session, label, marks))
        model_says_hidden += 1 if label["tokens_hid_intent"] else 0
        verdict = marks.get("verdict", "").strip().lower()
        if not verdict:
            verdicts["unreviewed"] += 1
        elif verdict not in VERDICTS:
            verdicts["invalid_verdict"] += 1
        else:
            verdicts[verdict] += 1
            by_intent.setdefault(label["intent"], Counter())[verdict] += 1
            bucket = "with_term_tokens" if _term_tokens(session) else "without_term_tokens"
            by_terms[bucket][verdict] += 1
        hidden = marks.get("tokens_hid_intent", "").strip().lower()
        if hidden in {"yes", "no"}:
            reviewer_says_hidden[hidden] += 1
    write_private_file(path, buffer.getvalue())
    rejected = Counter(label["reason"] for label in labels.values() if label["status"] == "rejected")
    return {
        "command": "review",
        "file": "intents/review.csv",
        "content_trust": CONTENT_TRUST,
        "labelled": sum(verdicts.values()),
        "rejected_replies": dict(rejected),
        "right": verdicts["right"],
        "wrong": verdicts["wrong"],
        "unsure": verdicts["unsure"],
        "unreviewed": verdicts["unreviewed"],
        "invalid_verdicts": verdicts["invalid_verdict"],
        "precision": _precision(verdicts),
        "precision_by_intent": {intent: _bucket(counts) for intent, counts in sorted(by_intent.items())},
        "term_token_effect": {
            **{bucket: _bucket(counts) for bucket, counts in by_terms.items()},
            "model_says_tokens_hid_intent": model_says_hidden,
            "reviewer_says_tokens_hid_intent": dict(reviewer_says_hidden),
        },
    }
