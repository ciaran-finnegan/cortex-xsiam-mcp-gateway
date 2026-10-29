"""Observers that turn work the gateway already does into tier-1 learned facts, at no extra quota.

- ``run_xql_query`` calls :func:`observe_xql_execution`: a cost-table sample (dataset, window
  bucket, selectivity class, units from ``query_cost`` or the drop in ``remaining_quota``); an
  absent-field fact from a classified ``unknown_field`` failure; an enum-like fact when an
  equality query returns no rows and the same query with ``contains`` returns rows later in
  the same engagement.
- ``discover_log_fields`` (and any field-cache fill) calls :func:`observe_field_catalog` with
  field names and value types.
- ``LearningMiddleware`` calls :func:`begin_tool_call` and :func:`end_tool_call`: one step
  record per query-running tool call (tool, times, query ids, units, outcome, and the bounded
  result when the engagement has a case), from which the learner derives helper usage,
  timings and the replay cache.

Observers only append to the learning journal (``learning_journal``); the learner process is
the single writer of fact files.

Observers read the query text the gateway submitted, response metadata, row counts, field
names and value types. They never read result cell values. Filter literals are held only as
hashes, in memory, to pair two queries, and are never written.
"""

import hashlib
import json
import logging
import re
import time
from collections import OrderedDict
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from config.config import get_config
from entities.MCPContext import MCPContext
from usecase import learned_store
from usecase.audit import stable_hash
from usecase.credential_broker import get_current_credential_selection
from usecase.identity import (
    IdentityAuthenticationError,
    default_mcp_context,
    resolve_mcp_context,
)
from usecase.learned_store import (
    FIELD_TYPES,
    IDENTIFIER_RE,
    Observation,
    get_pack_root,
    is_issued_query_id,
    register_query_id,
)
from usecase.learning_journal import (
    journal_fact_link,
    journal_observations,
    journal_tool_step,
)
from usecase.replay import current_case_id
from usecase.xql_discovery import MAX_DISCOVERY_FIELD_COUNT, extract_xql_rows

logger = logging.getLogger(__name__)

HOUR_MS = 3_600_000
DAY_MS = 86_400_000
ENUM_PAIR_TTL_SECONDS = 3600
MAX_PENDING_ENUM_PAIRS = 2000
MAX_ERROR_TEXT_CHARS = 4000

_IDENT = r"[A-Za-z_][A-Za-z0-9_.]*"
_DATASET_STAGE_RE = re.compile(r"^\s*dataset\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*$", re.IGNORECASE)
_STAGE_WORD_RE = re.compile(r"^\s*([A-Za-z_]+)")
_EQUALITY_RE = re.compile(r"(?<![!<>=])=(?!=)")
_IN_LIST_RE = re.compile(r"\bin\s*\(", re.IGNORECASE)
_CLAUSE_RE = re.compile(
    r"(?<![\w.])(?P<field>" + _IDENT + r")\s*(?P<op>(?<![!<>=])=(?!=)|\bcontains\b)\s*"
    r"(?P<literal>\"[^\"]*\"|'[^']*')",
    re.IGNORECASE,
)
_NEGATED_TAIL_RE = re.compile(r"\bnot\s*\(\s*$", re.IGNORECASE)
_TERMINAL_LIMIT_RE = re.compile(r"\|\s*limit\s+\d+\s*$", re.IGNORECASE)
_CONFIG_TIMEFRAME_RE = re.compile(
    r"\bconfig\b[^|]*?\btimeframe\s*=\s*(\d+)\s*(ms|mo|[smhdwy])(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
_DURATION_MS = {
    "ms": 1,
    "s": 1000,
    "m": 60_000,
    "h": HOUR_MS,
    "d": DAY_MS,
    "w": 7 * DAY_MS,
    "mo": 30 * DAY_MS,
    "y": 365 * DAY_MS,
}
_SAMPLE_STAGES = frozenset({"dataset", "fields", "limit", "sort"})
# Stages that read other sources, so the cost is not the first dataset's alone.
_MULTI_SOURCE_STAGES = frozenset({"join", "union", "call"})
# Stages that keep every dataset field visible to the stages after them.
_PASS_THROUGH_STAGES = frozenset({"filter", "sort", "limit"})
_FIELD_REFERENCE_STAGES = frozenset({"filter", "sort", "fields", "comp", "dedup"})
_XQL_KEYWORDS = frozenset(
    {
        "and", "as", "asc", "by", "comp", "config", "contains", "count", "dataset", "dedup", "desc",
        "false", "fields", "filter", "in", "limit", "not", "null", "or", "sort", "true",
    }
)
_UNKNOWN_FIELD_RES = (
    re.compile(
        r"(?:unknown|undefined|unrecognized|unrecognised|invalid|non[- ]?existent)\s+(?:field|column)s?"
        r"(?:\s+name)?\s*[:=]?\s*[\"'`]?(" + _IDENT + ")",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:field|column)\s+[\"'`]?(" + _IDENT + r")[\"'`]?\s+(?:does\s+not\s+exist|doesn't\s+exist|"
        r"is\s+not\s+defined|not\s+found|is\s+unknown|is\s+invalid|cannot\s+be\s+found)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:cannot|can't|could\s+not|unable\s+to)\s+(?:resolve|find)\s+(?:field|column)\s+[\"'`]?(" + _IDENT + ")",
        re.IGNORECASE,
    ),
)


# --- XQL shape parsing ---


@dataclass(frozen=True)
class ParsedQuery:
    """A query with comments blanked (``stripped``) and string contents blanked too (``masked``).

    Both strings keep the original length, so a span found in ``masked`` indexes ``stripped``.
    """

    stripped: str
    masked: str
    stages: tuple[tuple[int, int], ...]
    dataset: str | None

    def stage_word(self, index: int) -> str:
        start, end = self.stages[index]
        match = _STAGE_WORD_RE.match(self.masked[start:end])
        return match.group(1).lower() if match else ""

    def stage_text(self, index: int) -> str:
        start, end = self.stages[index]
        return self.masked[start:end]


def parse_xql(query: str) -> ParsedQuery:
    stripped = list(query)
    masked = list(query)
    index, length = 0, len(query)
    while index < length:
        char = query[index]
        if char in "\"'`":
            end = index + 1
            while end < length and query[end] != char:
                end += 2 if query[end] == "\\" else 1
            for position in range(index + 1, min(end, length)):
                masked[position] = "x"
            index = end + 1
        elif query.startswith("//", index):
            end = query.find("\n", index)
            end = length if end < 0 else end
            for position in range(index, end):
                stripped[position] = masked[position] = " "
            index = end
        elif query.startswith("/*", index):
            end = query.find("*/", index + 2)
            end = length if end < 0 else end + 2
            for position in range(index, end):
                stripped[position] = masked[position] = " "
            index = end
        else:
            index += 1
    masked_text = "".join(masked)
    stages = []
    start = 0
    for position, char in enumerate(masked_text):
        if char == "|":
            stages.append((start, position))
            start = position + 1
    stages.append((start, len(masked_text)))
    dataset_match = _DATASET_STAGE_RE.match(masked_text[stages[0][0] : stages[0][1]])
    return ParsedQuery(
        stripped="".join(stripped),
        masked=masked_text,
        stages=tuple(stages),
        dataset=dataset_match.group(1) if dataset_match else None,
    )


def window_ms(timeframe: Any, parsed: ParsedQuery | None = None) -> int | None:
    """Return the query window in milliseconds from the API timeframe and any ``config timeframe`` stage."""
    span = None
    if isinstance(timeframe, dict):
        relative = timeframe.get("relativeTime", timeframe.get("relative_time"))
        start, end = timeframe.get("from"), timeframe.get("to")
        if isinstance(relative, int) and not isinstance(relative, bool) and relative > 0:
            span = relative
        elif isinstance(start, int) and isinstance(end, int) and end > start:
            span = end - start
    if parsed is not None:
        match = _CONFIG_TIMEFRAME_RE.search(parsed.masked)
        if match:
            configured = int(match.group(1)) * _DURATION_MS[match.group(2).lower()]
            span = max(span or 0, configured)
    return span


def window_bucket(span_ms: int | None) -> str:
    if span_ms is None:
        return "unspecified"
    for limit, name in ((HOUR_MS, "le_1h"), (6 * HOUR_MS, "le_6h"), (DAY_MS, "le_24h"), (7 * DAY_MS, "le_7d"), (30 * DAY_MS, "le_30d")):
        if span_ms <= limit:
            return name
    return "gt_30d"


def selectivity_class(parsed: ParsedQuery) -> str:
    """Coarse selectivity: sample, unfiltered, filtered (no equality), or selective (equality or in-list)."""
    words = [parsed.stage_word(index) for index in range(len(parsed.stages))]
    filters = [parsed.stage_text(index) for index, word in enumerate(words) if word == "filter"]
    if not filters:
        return "sample" if set(words) <= _SAMPLE_STAGES else "unfiltered"
    if any(_EQUALITY_RE.search(text) or _IN_LIST_RE.search(text) for text in filters):
        return "selective"
    return "filtered"


def classify_xql_failure(detail: Any, query: str) -> dict[str, str] | None:
    """Classify an XSIAM failure message. Returns ``unknown_field`` only when the field it names is an
    identifier in the submitted query outside string literals, so the message cannot introduce new text.
    """
    if detail is None or not isinstance(query, str):
        return None
    text = detail if isinstance(detail, str) else json.dumps(detail, default=str)
    text = text[:MAX_ERROR_TEXT_CHARS]
    identifiers = set(re.findall(_IDENT, parse_xql(query).masked))
    for pattern in _UNKNOWN_FIELD_RES:
        for match in pattern.finditer(text):
            name = match.group(1).rstrip(".")
            if name in identifiers and name.lower() not in _XQL_KEYWORDS and IDENTIFIER_RE.match(name):
                return {"error_class": "unknown_field", "unknown_field": name}
    return None


def field_read_from_dataset(parsed: ParsedQuery, field_name: str) -> bool:
    """True when the first reference to a field reads it straight from the source dataset.

    Stages such as alter, comp or join create or drop fields, so an unknown field after them
    says nothing about the dataset itself.
    """
    if parsed.dataset is None:
        return False
    reference = re.compile(r"(?<![\w.])" + re.escape(field_name) + r"(?![\w.(])")
    alias = re.compile(r"\bas\s+" + re.escape(field_name) + r"(?![\w.])", re.IGNORECASE)
    for index in range(1, len(parsed.stages)):
        word = parsed.stage_word(index)
        text = parsed.stage_text(index)
        if reference.search(text):
            return word in _FIELD_REFERENCE_STAGES and not alias.search(text)
        if word not in _PASS_THROUGH_STAGES:
            return False
    return False


@dataclass(frozen=True)
class FilterClause:
    field: str
    operator: str
    value_sha256: str
    skeleton_sha256: str


def filter_clauses(parsed: ParsedQuery, window_key: str) -> list[FilterClause]:
    """Equality and contains clauses on string literals in filter stages, with a hash of the rest of the query."""
    clauses = []
    for index, (start, _) in enumerate(parsed.stages):
        if parsed.stage_word(index) != "filter":
            continue
        text = parsed.stage_text(index)
        for match in _CLAUSE_RE.finditer(text):
            if _NEGATED_TAIL_RE.search(text[: match.start()]):
                continue
            literal_start, literal_end = start + match.start("literal"), start + match.end("literal")
            value = parsed.stripped[literal_start + 1 : literal_end - 1]
            skeleton = parsed.stripped[: start + match.start()] + "\x00" + parsed.stripped[start + match.end() :]
            skeleton = _TERMINAL_LIMIT_RE.sub("| limit N", " ".join(skeleton.split()))
            clauses.append(
                FilterClause(
                    field=match.group("field"),
                    operator="=" if match.group("op") == "=" else "contains",
                    value_sha256=hashlib.sha256(value.encode()).hexdigest(),
                    skeleton_sha256=hashlib.sha256(f"{skeleton}\x00{window_key}".encode()).hexdigest(),
                )
            )
    return clauses


# --- State ---


@dataclass
class ToolCallObservation:
    tool: str
    principal: MCPContext
    engagement_key: str
    started_at: datetime
    started_monotonic: float
    query_ids: list[str] = field(default_factory=list)
    units: list[float] = field(default_factory=list)


_current_call: ContextVar[ToolCallObservation | None] = ContextVar("learning_tool_call", default=None)
_last_remaining: dict[str, float] = {}
_pending_enum_pairs: OrderedDict[tuple[str, ...], tuple[str, float]] = OrderedDict()


def reset_state() -> None:
    """Forget in-memory quota and pairing state. For tests."""
    _last_remaining.clear()
    _pending_enum_pairs.clear()


def _principal(ctx: Any) -> MCPContext:
    try:
        return resolve_mcp_context(ctx)
    except IdentityAuthenticationError:
        return default_mcp_context()


def engagement_key(ctx: Any, principal: MCPContext) -> str:
    """Key one engagement: the case when there is one, else the MCP session, always per principal."""
    case_id = current_case_id()
    session_id = None
    if case_id is None:
        try:
            session_id = getattr(ctx, "session_id", None)
        except Exception:
            session_id = None
    return stable_hash(
        [
            principal.principal_id,
            principal.tenant_id,
            principal.auth_source,
            case_id,
            session_id if isinstance(session_id, str) else None,
        ]
    )


def _learning_active() -> bool:
    try:
        return get_config().learning_enabled and get_pack_root() is not None
    except Exception:
        return False


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if number == number and abs(number) != float("inf") else None


def _query_units(response: dict[str, Any]) -> tuple[float | None, str | None]:
    reply = response.get("reply")
    reply = reply if isinstance(reply, dict) else {}
    selection = get_current_credential_selection()
    quota_key = selection.profile_name if selection is not None else "default"
    remaining = _finite_number(reply.get("remaining_quota"))
    previous = _last_remaining.get(quota_key)
    if remaining is not None:
        _last_remaining[quota_key] = remaining
    cost = reply.get("query_cost")
    if isinstance(cost, dict):
        # XSIAM may report cost per tenant; keep only the total so no tenant identifier is stored.
        values = [_finite_number(item) for item in cost.values()]
        cost = sum(values) if values and all(item is not None for item in values) else None
    cost = _finite_number(cost)
    if cost is not None and cost >= 0:
        return round(cost, 6), "query_cost"
    if remaining is not None and previous is not None and previous >= remaining:
        return round(previous - remaining, 6), "remaining_quota_delta"
    return None, None


def _row_count(response: dict[str, Any]) -> int:
    reply = response.get("reply")
    if isinstance(reply, dict):
        count = reply.get("number_of_results")
        if isinstance(count, int) and not isinstance(count, bool):
            return count
    return len(extract_xql_rows(response))


def _window_key(timeframe: Any) -> str:
    if not isinstance(timeframe, dict):
        return "none"
    return stable_hash({key: timeframe.get(key) for key in ("relativeTime", "relative_time", "from", "to")})


def _enum_observations(
    key: str,
    parsed: ParsedQuery,
    timeframe: Any,
    rows: int,
    query_id: str,
) -> list[Observation]:
    observations = []
    now = time.monotonic()
    for expired, (_, seen) in list(_pending_enum_pairs.items()):
        if now - seen <= ENUM_PAIR_TTL_SECONDS:
            break
        del _pending_enum_pairs[expired]
    for clause in filter_clauses(parsed, _window_key(timeframe)):
        pair_key = (key, parsed.dataset, clause.field, clause.value_sha256, clause.skeleton_sha256)
        fact = {"field": clause.field, "operator": "contains"}
        if clause.operator == "=":
            if rows == 0:
                _pending_enum_pairs[pair_key] = (query_id, now)
                _pending_enum_pairs.move_to_end(pair_key)
                while len(_pending_enum_pairs) > MAX_PENDING_ENUM_PAIRS:
                    _pending_enum_pairs.popitem(last=False)
            else:
                # Equality matched rows, so the field is not enum-like.
                observations.append(
                    Observation("enum_fields", fact, (query_id,), "query_pair_outcome", parsed.dataset, effect="contradict")
                )
        elif rows > 0:
            pending = _pending_enum_pairs.pop(pair_key, None)
            if pending is not None:
                observations.append(
                    Observation("enum_fields", fact, (pending[0], query_id), "query_pair_outcome", parsed.dataset)
                )
    return observations


# --- Observers ---


async def observe_xql_execution(
    ctx: Any,
    *,
    query: str,
    timeframe: Any,
    response: dict[str, Any],
    duration_ms: float,
) -> None:
    """Learn from one executed query. Telemetry only: never raises, never alters the response."""
    try:
        query_id = register_query_id(response.get("query_id"))
        if query_id is None:
            return
        units, units_source = _query_units(response)
        call = _current_call.get()
        if call is not None:
            call.query_ids.append(query_id)
            if units is not None:
                call.units.append(units)
        if not _learning_active():
            return
        parsed = parse_xql(query)
        if parsed.dataset is None:
            return
        principal = call.principal if call is not None else _principal(ctx)
        key = call.engagement_key if call is not None else engagement_key(ctx, principal)
        observations: list[Observation] = []
        if not response.get("error"):
            words = {parsed.stage_word(index) for index in range(len(parsed.stages))}
            if units is not None and not words & _MULTI_SOURCE_STAGES:
                observations.append(
                    Observation(
                        "cost_table",
                        {
                            "window_bucket": window_bucket(window_ms(timeframe, parsed)),
                            "selectivity": selectivity_class(parsed),
                            "units": units,
                            "units_source": units_source,
                        },
                        (query_id,),
                        "query_metadata",
                        parsed.dataset,
                        effect="measure",
                    )
                )
            observations.extend(_enum_observations(key, parsed, timeframe, _row_count(response), query_id))
        elif response.get("error_class") == "unknown_field":
            field_name = response.get("unknown_field")
            if isinstance(field_name, str) and field_read_from_dataset(parsed, field_name):
                fact = {"field": field_name}
                observations.append(Observation("absent_fields", fact, (query_id,), "query_error_class", parsed.dataset))
                observations.append(
                    Observation("schema", fact, (query_id,), "query_error_class", parsed.dataset, effect="contradict")
                )
        journal_observations(observations, principal=principal, trigger="xql_query", engagement=key)
    except Exception as e:
        logger.warning("Learning observer skipped an XQL result: %s", type(e).__name__)


async def observe_field_catalog(
    ctx: Any,
    *,
    dataset: str,
    fields: list[dict[str, Any]],
    query_id: Any,
    source_class: str = "field_discovery_sample",
) -> None:
    """Learn field names and value types from a discovery sample or field-cache fill. Never raises.

    ``fields`` is the output of ``infer_field_catalog``: names and inferred types only.
    """
    try:
        if not _learning_active() or not is_issued_query_id(query_id):
            return
        observations: list[Observation] = []
        for item in fields[:MAX_DISCOVERY_FIELD_COUNT]:
            name = item.get("name") if isinstance(item, dict) else None
            if not isinstance(name, str) or not IDENTIFIER_RE.match(name):
                continue
            types = [value for value in (item.get("observed_types") or [item.get("type")]) if value != "null"]
            if not types:
                continue
            field_type = types[0] if len(types) == 1 else "mixed"
            if field_type not in FIELD_TYPES:
                continue
            observations.append(
                Observation("schema", {"field": name, "type": field_type}, (query_id,), source_class, dataset)
            )
            observations.append(
                Observation("absent_fields", {"field": name}, (query_id,), source_class, dataset, effect="contradict")
            )
        call = _current_call.get()
        principal = call.principal if call is not None else _principal(ctx)
        key = call.engagement_key if call is not None else engagement_key(ctx, principal)
        journal_observations(observations, principal=principal, trigger="field_catalog", engagement=key)
    except Exception as e:
        logger.warning("Learning observer skipped a field catalog: %s", type(e).__name__)


def begin_tool_call(tool: str, ctx: Any) -> Token:
    try:
        principal = _principal(ctx)
        observation = ToolCallObservation(
            tool=tool,
            principal=principal,
            engagement_key=engagement_key(ctx, principal),
            started_at=learned_store.now_utc(),
            started_monotonic=time.monotonic(),
        )
    except Exception as e:
        logger.warning("Learning observer cannot track a tool call: %s", type(e).__name__)
        observation = None
    return _current_call.set(observation)


async def end_tool_call(
    token: Token,
    *,
    outcome: str,
    payload: Any,
    arguments: dict[str, Any] | None,
) -> None:
    """Journal one finished tool call for the learner: the step, and any engagement fact link. Never raises.

    The learner derives helper usage, tool durations and the gaps between steps from these records
    when the engagement closes, so every replica's steps are combined in one place.
    """
    call = _current_call.get()
    _current_call.reset(token)
    if call is None:
        return
    try:
        outcome = "success" if outcome == "success" else "error"
        case_id = current_case_id()
        if call.tool == "record_fact" and outcome == "success" and case_id and isinstance(arguments, dict):
            journal_fact_link(
                engagement_key=call.engagement_key,
                case_id=case_id,
                key=arguments.get("key"),
                evidence_query_id=arguments.get("evidence_query_id"),
            )
        if not call.query_ids:
            return
        journal_tool_step(
            principal=call.principal,
            engagement_key=call.engagement_key,
            case_id=case_id,
            tool=call.tool,
            started_at=call.started_at,
            ended_at=learned_store.now_utc(),
            duration_ms=(time.monotonic() - call.started_monotonic) * 1000,
            query_ids=call.query_ids,
            units=sum(call.units) if len(call.units) == len(call.query_ids) else None,
            outcome=outcome,
            arguments=arguments,
            payload=payload,
        )
    except Exception as e:
        logger.warning("Learning observer skipped a tool call: %s", type(e).__name__)
