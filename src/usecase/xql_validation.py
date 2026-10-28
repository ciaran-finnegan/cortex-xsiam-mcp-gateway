"""Static checks for analyst-authored XQL, run before the query spends quota.

``validate_query`` never runs the caller's query as written. It strips comments, splits the query
into stages and checks the terminal limit, the timeframe, the dataset (policy first, then
existence), field names against the discovered schema, ``=`` on enum-backed fields and
``contains`` on IP address literals. The only XSIAM queries it may issue are a field-discovery
sample, at most once per credential profile and dataset per hour, and, when the caller asks for
it, a probe of the query over one hour with ``| limit 1``.

Security properties:

- Dataset policy is applied before any lookup, so neither existence checks, field discovery nor
  suggestions reveal anything about a dataset the principal cannot query.
- ``corrected_query`` comes only from the deterministic rewrites in this module, never a model.
- Messages are gateway-authored. The only caller or tenant text they carry is identifiers that
  pass the identifier check.
- The probe runs raw XQL, so it requires the same grants as ``execute_xql_query``.
"""

import difflib
import fnmatch
import importlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from typing import Any

from config.config import get_config
from entities.exceptions import PAPIClientError
from entities.MCPContext import MCPContext
from usecase.credential_broker import CredentialBrokerError, select_xsiam_credentials
from usecase.dataset_query import QueryTimeframe
from usecase.fetcher import get_fetcher
from usecase.log_policy import (
    ALL_DATASETS,
    authorize_dataset,
    ensure_raw_xql_authorized,
)
from usecase.xql_builder import (
    SAFE_IDENTIFIER_RE,
    TERMINAL_LIMIT_RE,
    enforce_terminal_xql_limit,
    strip_xql_comments,
)
from usecase.xql_discovery import (
    build_field_discovery_xql,
    extract_xql_rows,
    normalize_dataset_record,
)
from usecase.xql_docs import DOCS_GUIDANCE, problem_docs
from usecase.xql_errors import XQL_ERROR_CLASSES, xql_error_details
from usecase.xql_executor import run_xql_query

HOUR_MS = 3_600_000
DAY_MS = 24 * HOUR_MS
APPENDED_LIMIT = 25
CACHE_TTL_SECONDS = 3600
CACHE_MAX_ENTRIES = 256
FIELD_DISCOVERY_SAMPLE = 25
FIELD_DISCOVERY_WINDOW_MS = 7 * DAY_MS
PROBE_WINDOW_MS = HOUR_MS
PROBE_TIMEOUT_SECONDS = 30
MAX_SUGGESTIONS = 3

# Vendor-standard enum-backed fields. On some tenants these return no rows for = "VALUE" in a row
# filter although comp ... by shows the value; contains matches. Operators add their own with
# XQL_ENUM_FIELDS.
BUILTIN_ENUM_FIELDS: dict[str, tuple[str, ...]] = {
    "alerts": ("alert_source",),
    "management_auditing": ("management_auditing_type",),
    "xdr_data": ("event_type", "event_sub_type"),
}

_CHECKED_STAGES = frozenset({"filter", "fields", "alter", "comp", "sort", "dedup"})
# Stages that keep field names as they are. Any other stage ends field checking.
_PRESERVING_STAGES = frozenset({"limit", "bin", "replacenull", "tag", "search", "config"})
_SOURCE_STAGES = frozenset({"dataset", "preset", "datamodel"})
_KEYWORDS = frozenset(
    {
        "and", "or", "not", "in", "contains", "incidr", "incidr6", "incidrlist", "like", "is",
        "true", "false", "null", "as", "by", "asc", "desc", "addrawdata",
    }
)
_OPEN = frozenset({"(", "[", "{"})
_CLOSE = frozenset({")", "]", "}"})

_TOKEN_RE = re.compile(
    r"(?P<ws>\s+)"
    r'|(?P<string>"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')'
    r"|(?P<qident>`[^`\n]*`)"
    r"|(?P<number>\d+(?:\.\d+)?[A-Za-z]*)"
    r"|(?P<ident>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r"|(?P<op>->|!=|~=|>=|<=|==|[=<>|(),\[\]{}+\-*/%:;!])"
    r"|(?P<other>.)"
)

_TIMEFRAME_KEYS = {
    "relative_ms": "relative_ms",
    "relativeTime": "relative_ms",
    "from_ms": "from_ms",
    "from": "from_ms",
    "to_ms": "to_ms",
    "to": "to_ms",
}

_field_cache: dict[tuple[str, str], tuple[float, frozenset[str], str]] = {}
_dataset_cache: dict[str, tuple[float, frozenset[str]]] = {}


def reset_caches() -> None:
    _field_cache.clear()
    _dataset_cache.clear()


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    start: int
    end: int

    @property
    def name(self) -> str:
        return self.text.strip("`") if self.kind == "qident" else self.text

    def is_op(self, *texts: str) -> bool:
        return self.kind == "op" and self.text in texts

    def is_word(self, *words: str) -> bool:
        return self.kind == "ident" and self.text.lower() in words


@dataclass(frozen=True)
class Problem:
    code: str
    message: str
    severity: str = "error"
    field: str | None = None
    suggestion: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "severity": self.severity, "message": self.message}
        if self.field:
            result["field"] = self.field
        if self.suggestion:
            result["suggestion"] = self.suggestion
        result["docs"] = problem_docs(self.code)
        return result


@dataclass(frozen=True)
class Rewrite:
    start: int
    end: int
    replacement: str


# --- Entry point ---


async def validate_query(
    ctx,
    principal: MCPContext,
    query: Any,
    *,
    timeframe: Any = None,
    probe: bool = False,
) -> dict[str, Any]:
    problems: list[Problem] = []
    if not isinstance(query, str) or not query.strip():
        return _result([Problem("query_invalid", "The query is empty.")])
    max_chars = get_config().xql_max_query_chars
    if len(query) > max_chars:
        return _result([Problem("query_invalid", f"The query exceeds the configured {max_chars}-character limit.")])
    try:
        stripped = strip_xql_comments(query).strip()
    except ValueError:
        return _result([Problem("query_invalid", "The query has an unterminated /* block comment.")])
    tokens = tokenize(stripped)
    if any(token.kind == "other" and token.text in "\"'`" for token in tokens):
        return _result([Problem("query_invalid", "The query has an unterminated string literal or quoted name.")])

    typed_timeframe = _check_timeframe(timeframe, problems)
    rewrites: list[Rewrite] = []
    append_limit = _check_limit(stripped, problems)

    stages = split_stages(tokens)
    keywords = [_stage_keyword(stage) for stage in stages]
    has_config_timeframe = any(
        keyword == "config" and any(token.is_word("timeframe") for token in stage)
        for keyword, stage in zip(keywords, stages, strict=True)
    )
    if has_config_timeframe:
        problems.append(
            Problem(
                "config_timeframe",
                "The query sets its own window with config timeframe, which overrides the API timeframe.",
                severity="warning",
                suggestion="Remove config timeframe and pass the window as the timeframe argument.",
            )
        )

    source_index = next((index for index, keyword in enumerate(keywords) if keyword != "config"), len(keywords))
    source_keyword = keywords[source_index] if source_index < len(keywords) else ""
    source_dataset = _source_dataset(stages[source_index]) if source_keyword == "dataset" else None
    datasets = dataset_references(tokens)
    allowed_datasets = _check_datasets(principal, source_keyword, datasets, keywords, problems)

    enum_fields = _enum_fields(datasets)
    for stage, keyword in zip(stages, keywords, strict=True):
        if keyword == "filter":
            _check_filter_comparisons(stage, enum_fields, problems, rewrites)

    field_check = {"status": "skipped", "source": None}
    if allowed_datasets:
        scope = _cache_scope(principal)
        missing = await _check_dataset_existence(ctx, principal, scope, allowed_datasets, problems)
        if source_dataset in allowed_datasets and not missing:
            field_check = await _check_fields(
                ctx, scope, source_dataset, stages[source_index + 1 :], keywords[source_index + 1 :], problems
            )

    corrected = _apply_rewrites(stripped, rewrites, append_limit)
    runnable = corrected or stripped
    probe_result = None
    if probe:
        if any(problem.severity == "error" for problem in problems):
            probe_result = {"ran": False, "reason": "static_checks_failed"}
        else:
            probe_result = await _run_probe(ctx, principal, runnable, typed_timeframe, has_config_timeframe)
            failure = _probe_problem(probe_result)
            if failure is not None:
                problems.append(failure)

    return _result(
        problems,
        corrected_query=corrected,
        estimate=_cost_estimate(runnable, typed_timeframe),
        datasets=datasets,
        field_check=field_check,
        probe=probe_result,
    )


def _result(
    problems: list[Problem],
    *,
    corrected_query: str | None = None,
    estimate: dict[str, Any] | None = None,
    datasets: list[str] | None = None,
    field_check: dict[str, Any] | None = None,
    probe: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "success": True,
        "ok": not any(problem.severity == "error" for problem in problems),
        "problems": [problem.to_dict() for problem in problems],
        "corrected_query": corrected_query,
        "estimate": estimate,
        "datasets": datasets or [],
        "field_check": field_check or {"status": "skipped", "source": None},
        "probe": probe,
        "executed": bool(probe and probe.get("ran")),
        "docs_guidance": DOCS_GUIDANCE,
    }


# --- Parsing ---


def tokenize(query: str) -> list[Token]:
    tokens = []
    for match in _TOKEN_RE.finditer(query):
        kind = match.lastgroup or "other"
        if kind != "ws":
            tokens.append(Token(kind, match.group(), match.start(), match.end()))
    return tokens


def split_stages(tokens: list[Token]) -> list[list[Token]]:
    """Split top-level stages on pipes outside brackets; subqueries stay inside their stage."""
    stages: list[list[Token]] = [[]]
    depth = 0
    for token in tokens:
        if token.is_op(*_OPEN):
            depth += 1
        elif token.is_op(*_CLOSE):
            depth = max(depth - 1, 0)
        elif token.is_op("|") and depth == 0:
            stages.append([])
            continue
        stages[-1].append(token)
    return [stage for stage in stages if stage]


def dataset_references(tokens: list[Token]) -> list[str]:
    """Return dataset names from dataset stages, including subqueries, and union stages, in order."""
    names: list[str] = []
    for index, token in enumerate(tokens):
        previous = tokens[index - 1] if index else None
        at_stage_start = previous is None or previous.is_op("|", "(")
        following = tokens[index + 1 : index + 3]
        if token.is_word("dataset") and at_stage_start and following:
            if following[0].is_op("=") and len(following) == 2 and following[1].kind == "ident":
                names.append(following[1].text)
            elif following[0].is_word("in"):
                for item in tokens[index + 3 :]:
                    if item.is_op(")"):
                        break
                    if item.kind == "ident":
                        names.append(item.text)
        elif token.is_word("union") and at_stage_start and following and following[0].kind == "ident":
            names.append(following[0].text)
    unique: dict[str, str] = {}
    for name in names:
        unique.setdefault(name.lower(), name)
    return list(unique.values())


def _source_dataset(stage: list[Token]) -> str | None:
    """The dataset named by a 'dataset = name' source stage; None for 'dataset in (...)'."""
    if len(stage) == 3 and stage[1].is_op("=") and stage[2].kind == "ident":
        return stage[2].text
    return None


def _stage_keyword(stage: list[Token]) -> str:
    return stage[0].text.lower() if stage and stage[0].kind == "ident" else ""


def _split_top_level(tokens: list[Token]) -> list[list[Token]]:
    parts: list[list[Token]] = [[]]
    depth = 0
    for token in tokens:
        if token.is_op(*_OPEN):
            depth += 1
        elif token.is_op(*_CLOSE):
            depth = max(depth - 1, 0)
        elif depth == 0 and token.is_op(","):
            parts.append([])
            continue
        parts[-1].append(token)
    return [part for part in parts if part]


def field_references(stage: list[Token]) -> tuple[list[Token], set[str]]:
    """Return (field tokens referenced, names defined) by one filter, fields, alter, comp, sort or dedup stage."""
    keyword = _stage_keyword(stage)
    body = stage[1:]
    refs: list[Token] = []
    defined: set[str] = set()
    if keyword == "fields" and any(token.is_op("*") for token in body):
        return refs, defined
    parts = _split_top_level(body) if keyword == "alter" else [body]
    for part in parts:
        if keyword == "alter" and len(part) >= 2 and part[0].kind in ("ident", "qident") and part[1].is_op("="):
            defined.add(part[0].name.lower())
            part = part[2:]
        for index, token in enumerate(part):
            if token.kind not in ("ident", "qident"):
                continue
            previous = part[index - 1] if index else None
            following = part[index + 1] if index + 1 < len(part) else None
            if previous is not None and previous.is_word("as"):
                defined.add(token.name.lower())
            elif token.kind == "ident" and (token.text.lower() in _KEYWORDS or token.text.upper().startswith("ENUM.")):
                continue
            elif following is not None and following.is_op("("):
                continue
            elif previous is not None and previous.is_op("->"):
                continue
            else:
                refs.append(token)
    return refs, defined


# --- Checks ---


def _check_timeframe(timeframe: Any, problems: list[Problem]) -> QueryTimeframe | None:
    if timeframe is None:
        problems.append(
            Problem(
                "timeframe_missing",
                "No timeframe was given. XSIAM then searches its default window, and broad searches can time out.",
                suggestion='Pass {"from_ms": <epoch ms>, "to_ms": <epoch ms>}; absolute windows are the most reliable.',
            )
        )
        return None
    invalid = Problem(
        "timeframe_invalid",
        "Use {from_ms, to_ms} with from_ms < to_ms, or {relative_ms}, as integer milliseconds.",
    )
    if not isinstance(timeframe, dict):
        problems.append(invalid)
        return None
    mapped: dict[str, int] = {}
    for key, value in timeframe.items():
        target = _TIMEFRAME_KEYS.get(key)
        if target is None or target in mapped or isinstance(value, bool) or not isinstance(value, int) or value < 0:
            problems.append(invalid)
            return None
        mapped[target] = value
    relative = "relative_ms" in mapped
    absolute = "from_ms" in mapped or "to_ms" in mapped
    if relative == absolute:
        problems.append(invalid)
        return None
    if relative:
        span = mapped["relative_ms"]
    elif "from_ms" in mapped and "to_ms" in mapped and mapped["from_ms"] < mapped["to_ms"]:
        span = mapped["to_ms"] - mapped["from_ms"]
    else:
        problems.append(invalid)
        return None
    if span <= 0:
        problems.append(invalid)
        return None

    max_span = get_config().dataset_query_max_timeframe_ms
    if max_span > 0 and span > max_span:
        problems.append(
            Problem(
                "timeframe_too_long",
                f"The timeframe spans {_days(span)} days; the configured maximum is {_days(max_span)} days.",
                suggestion="Narrow the window, or split the question into several shorter windows.",
            )
        )
        return None
    try:
        typed = QueryTimeframe.model_validate(mapped)
    except ValueError:
        problems.append(invalid)
        return None

    mode_window = _mode_window_ms()
    if mode_window and span > mode_window:
        problems.append(
            Problem(
                "timeframe_exceeds_mode_window",
                f"The timeframe spans {_days(span)} days; the current engagement mode defaults to {_days(mode_window)} days.",
                severity="warning",
                suggestion="Start with the mode's default window and widen it only if the answer needs it.",
            )
        )
    return typed


def _check_limit(stripped: str, problems: list[Problem]) -> bool:
    """Check the terminal limit. Returns True when a limit should be appended to the corrected query."""
    match = TERMINAL_LIMIT_RE.search(stripped)
    if match is None:
        problems.append(
            Problem(
                "missing_limit",
                "Raw XQL must end with a numeric '| limit N' stage.",
                suggestion=f"Append '| limit {APPENDED_LIMIT}'.",
            )
        )
        return True
    requested = int(match.group(1))
    maximum = get_config().dataset_query_max_rows
    if requested < 1:
        problems.append(Problem("limit_invalid", "The terminal limit must be at least 1."))
    elif requested > maximum:
        problems.append(
            Problem(
                "limit_clamped",
                f"The terminal limit {requested} is above the configured maximum; the gateway runs it as {maximum}.",
                severity="warning",
            )
        )
    return False


def _check_datasets(
    principal: MCPContext,
    source_keyword: str,
    datasets: list[str],
    keywords: list[str],
    problems: list[Problem],
) -> list[str]:
    """Apply dataset policy. Returns the referenced datasets the principal may query."""
    if source_keyword not in _SOURCE_STAGES:
        problems.append(
            Problem(
                "no_dataset",
                "The query does not start with a dataset stage, so XSIAM would search its default query target.",
                suggestion="Start the query with 'dataset = <name>'.",
            )
        )
        return []
    if source_keyword != "dataset" or "call" in keywords:
        problems.append(
            Problem(
                "dataset_unresolved",
                "The query reads a preset, data model or saved query, so its datasets cannot be checked against dataset policy here.",
                severity="warning",
            )
        )
    allowed = []
    for name in datasets:
        if not SAFE_IDENTIFIER_RE.match(name):
            continue
        if authorize_dataset(principal, name).allowed:
            allowed.append(name)
        else:
            problems.append(
                Problem(
                    "dataset_not_allowed",
                    f"Dataset policy does not allow this principal to query dataset {name}.",
                    suggestion="Use list_log_datasets to see the datasets you may query.",
                )
            )
    return allowed


async def _check_dataset_existence(
    ctx,
    principal: MCPContext,
    scope: str,
    datasets: list[str],
    problems: list[Problem],
) -> bool:
    """Flag allowed datasets the tenant does not have. Returns True when any is missing."""
    names = await _tenant_dataset_names(ctx, scope)
    if names is None:
        return False
    known = {name.lower() for name in names}
    missing = False
    for dataset in datasets:
        if dataset.lower() in known:
            continue
        missing = True
        allowed_names = [name for name in names if SAFE_IDENTIFIER_RE.match(name) and authorize_dataset(principal, name).allowed]
        problems.append(
            Problem(
                "unknown_dataset",
                f"Dataset {dataset} does not exist on this tenant.",
                suggestion=_did_you_mean(dataset, allowed_names) or "Use list_log_datasets to find the dataset name.",
            )
        )
    return missing


async def _check_fields(
    ctx,
    scope: str,
    dataset: str,
    stages: list[list[Token]],
    keywords: list[str],
    problems: list[Problem],
) -> dict[str, Any]:
    """Check field names in the stages after the source stage against the discovered schema."""
    discovered, source = await _dataset_fields(ctx, scope, dataset)
    if not discovered:
        reason = (
            f"Field discovery found no rows in dataset {dataset} over the last {_days(FIELD_DISCOVERY_WINDOW_MS)} days, "
            "so field names were not checked. The dataset may not be receiving data."
            if source != "unavailable"
            else "Field discovery is unavailable, so field names were not checked."
        )
        problems.append(Problem("field_check_skipped", reason, severity="warning"))
        return {"status": "skipped", "source": source}

    known = {name.lower() for name in discovered}
    stopped_at = None
    reported: set[str] = set()
    for stage, keyword in zip(stages, keywords, strict=True):
        if keyword in _PRESERVING_STAGES:
            continue
        if keyword not in _CHECKED_STAGES:
            stopped_at = keyword or "unrecognised"
            break
        refs, defined = field_references(stage)
        known |= defined
        for token in refs:
            lowered = token.name.lower()
            if lowered in known or lowered.split(".", 1)[0] in known or lowered in reported:
                continue
            reported.add(lowered)
            safe_name = token.name if SAFE_IDENTIFIER_RE.match(token.name) else None
            problems.append(
                Problem(
                    "unknown_field",
                    f"Field {safe_name or '(quoted name)'} in the {keyword} stage is not among the fields discovered in dataset {dataset}.",
                    field=safe_name,
                    suggestion=_did_you_mean(token.name, sorted(discovered))
                    or f"Run discover_log_fields for {dataset} with field_name_contains to find the right name.",
                )
            )
    if stopped_at is not None:
        problems.append(
            Problem(
                "field_check_skipped",
                f"Fields used from the {stopped_at} stage onward were not checked.",
                severity="warning",
            )
        )
        return {"status": "partial", "source": source}
    return {"status": "checked", "source": source}


def _check_filter_comparisons(
    stage: list[Token],
    enum_fields: set[str],
    problems: list[Problem],
    rewrites: list[Rewrite],
) -> None:
    """Flag = on enum-backed fields and contains on an IP address literal, with deterministic rewrites."""
    for index, token in enumerate(stage):
        if token.kind != "ident" or token.text.lower() in _KEYWORDS:
            continue
        previous = stage[index - 1] if index else None
        if previous is not None and previous.is_op("->"):
            continue
        rest = stage[index + 1 : index + 4]
        if (
            len(rest) >= 2
            and rest[0].is_op("=", "==", "!=")
            and rest[1].kind == "string"
            and token.text.lower() in enum_fields
        ):
            negated = rest[0].text == "!="
            replacement = f"{token.text} contains {rest[1].text}"
            if negated:
                replacement = f"not ({replacement})"
            rewrites.append(Rewrite(token.start, rest[1].end, replacement))
            problems.append(
                Problem(
                    "enum_equality",
                    f"Field {token.text} is enum-backed. Comparing it with {rest[0].text} and a string can return no rows "
                    "even when the value exists; contains matches, and so does a comparison with ENUM.<NAME>.",
                    field=token.text,
                    suggestion=replacement,
                )
            )
            continue
        negated = len(rest) >= 3 and rest[0].is_word("not") and rest[1].is_word("contains")
        operator_index = 1 if negated else 0
        if len(rest) < operator_index + 2 or not rest[operator_index].is_word("contains"):
            continue
        literal = rest[operator_index + 1]
        address = _address_literal(literal)
        if address is None:
            continue
        replacement = f"{token.text} {'not in' if negated else 'in'} ({literal.text})"
        rewrites.append(Rewrite(token.start, literal.end, replacement))
        problems.append(
            Problem(
                "contains_on_address",
                f"contains matches substrings, so {address} also matches longer addresses that contain it. "
                "Use an exact match, or incidr for a range.",
                field=token.text,
                suggestion=replacement,
            )
        )


# --- Lookups and caches ---


def _cache_scope(principal: MCPContext) -> str:
    try:
        profile = select_xsiam_credentials(principal, {}).profile_name
    except CredentialBrokerError:
        profile = "unresolved"
    return f"{principal.tenant_id or '-'}|{profile}"


async def _tenant_dataset_names(ctx, scope: str) -> frozenset[str] | None:
    """Dataset names from the get_datasets API, cached per credential scope. get_datasets spends no query quota."""
    now = time.monotonic()
    cached = _dataset_cache.get(scope)
    if cached and now - cached[0] < CACHE_TTL_SECONDS:
        return cached[1]
    try:
        fetcher = await get_fetcher(ctx)
        response = await fetcher.send_request("/xql/get_datasets", data={"request_data": {}})
    except (PAPIClientError, CredentialBrokerError):
        return None
    reply = response.get("reply") if isinstance(response, dict) else None
    if not isinstance(reply, list):
        return None
    names = frozenset(
        name
        for item in reply
        if isinstance(item, dict) and isinstance(name := normalize_dataset_record(item).get("dataset_name"), str) and name
    )
    _store(_dataset_cache, scope, (now, names))
    return names


async def _dataset_fields(ctx, scope: str, dataset: str) -> tuple[frozenset[str], str]:
    """Observed field names for an allowed dataset, discovered at most once per scope and dataset per hour."""
    key = (scope, dataset.lower())
    now = time.monotonic()
    cached = _field_cache.get(key)
    if cached and now - cached[0] < CACHE_TTL_SECONDS:
        return cached[1], "cache" if cached[1] else cached[2]
    now_ms = int(time.time() * 1000)
    try:
        response = await run_xql_query(
            ctx,
            build_field_discovery_xql(dataset, FIELD_DISCOVERY_SAMPLE),
            FIELD_DISCOVERY_SAMPLE,
            timeframe={"from": now_ms - FIELD_DISCOVERY_WINDOW_MS, "to": now_ms},
            timeout_seconds=PROBE_TIMEOUT_SECONDS,
        )
    except (PAPIClientError, CredentialBrokerError, PermissionError, ValueError):
        response = {"error": "unavailable"}
    if response.get("error"):
        names: frozenset[str] = frozenset()
        source = "unavailable"
    else:
        names = frozenset(name for row in extract_xql_rows(response) for name in row if isinstance(name, str))
        source = "discovery"
    # Failures and empty samples are cached too, so discovery runs at most once an hour.
    _store(_field_cache, key, (now, names, source))
    return names, source


def _store(cache: dict, key, value) -> None:
    if key not in cache and len(cache) >= CACHE_MAX_ENTRIES:
        cache.pop(next(iter(cache)))
    cache[key] = value


def _enum_fields(datasets: list[str]) -> set[str]:
    """Enum-backed field names for the referenced datasets, from built-ins, XQL_ENUM_FIELDS and the catalogue."""
    configured = _parse_enum_fields(get_config().xql_enum_fields)
    fields: set[str] = set()
    for dataset in datasets:
        lowered = dataset.lower()
        fields.update(name.lower() for name in BUILTIN_ENUM_FIELDS.get(lowered, ()))
        for pattern, names in configured.items():
            if fnmatch.fnmatchcase(lowered, pattern):
                fields.update(names)
        fields.update(_catalogue_enum_fields(dataset))
    return fields


def _parse_enum_fields(raw: str) -> dict[str, tuple[str, ...]]:
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid XQL_ENUM_FIELDS JSON: {e.msg}") from e
    if not isinstance(parsed, dict):
        raise ValueError("XQL_ENUM_FIELDS must be a JSON object mapping dataset names or patterns to field lists")
    result: dict[str, tuple[str, ...]] = {}
    for pattern, names in parsed.items():
        if not isinstance(names, list) or not all(isinstance(name, str) and SAFE_IDENTIFIER_RE.match(name) for name in names):
            raise ValueError(f"XQL_ENUM_FIELDS entry {pattern} must be a list of field names")
        result[str(pattern).lower()] = tuple(name.lower() for name in names)
    return result


def _catalogue_enum_fields(dataset: str) -> set[str]:
    """Enum-backed fields an authored catalogue entry declares, when the catalogue module is installed."""
    catalogue = _optional_module("usecase.dataset_catalogue")
    try:
        resolved = catalogue.get_catalogue().resolve(dataset)
        names = getattr(resolved.entry, "enum_fields", None) or ()
    except Exception:
        return set()
    return {name.lower() for name in names if isinstance(name, str) and SAFE_IDENTIFIER_RE.match(name)}


def _mode_window_ms() -> int | None:
    engagement = _optional_module("usecase.engagement")
    try:
        window = engagement.get_mode_policy().default_window_ms
    except Exception:
        return None
    return window if isinstance(window, int) and window > 0 else None


def _cost_estimate(query: str, timeframe: QueryTimeframe | None) -> dict[str, Any] | None:
    cost_guard = _optional_module("usecase.cost_guard")
    if cost_guard is None or timeframe is None:
        return None
    try:
        return cost_guard.estimate_xql(query, timeframe).to_dict()
    except Exception:
        return None


def _optional_module(name: str):
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


# --- Probe ---


async def _run_probe(
    ctx,
    principal: MCPContext,
    query: str,
    timeframe: QueryTimeframe | None,
    has_config_timeframe: bool,
) -> dict[str, Any]:
    try:
        ensure_raw_xql_authorized(principal)
        if not authorize_dataset(principal, ALL_DATASETS).allowed:
            raise PermissionError("all-datasets grant required")
    except PermissionError:
        return {
            "ran": False,
            "reason": "not_authorized",
            "message": "The probe runs raw XQL, so it needs the same privileged group and all-datasets grant as execute_xql_query.",
        }
    if has_config_timeframe:
        return {
            "ran": False,
            "reason": "config_timeframe",
            "message": "The probe cannot bound a query that sets config timeframe; remove it first.",
        }
    window = probe_window(timeframe)
    try:
        response = await run_xql_query(
            ctx,
            enforce_terminal_xql_limit(query, 1),
            1,
            timeframe=window,
            timeout_seconds=PROBE_TIMEOUT_SECONDS,
        )
    except PermissionError as e:
        return {"ran": False, "reason": "refused", "message": str(e)[:500]}
    except (PAPIClientError, CredentialBrokerError) as e:
        return {"ran": False, "reason": "xsiam_unavailable", "message": type(e).__name__}
    except ValueError as e:
        return {"ran": False, "reason": "invalid", "message": str(e)[:500]}
    result: dict[str, Any] = {"ran": True, "query_id": response.get("query_id"), "timeframe": window}
    if response.get("error"):
        return {**result, "ok": False, "error": response["error"], **xql_error_details(response)}
    return {**result, "ok": True, "rows_returned": min(len(extract_xql_rows(response)), 1)}


def probe_window(timeframe: QueryTimeframe | None) -> dict[str, int]:
    """One hour ending at the caller's absolute end time, or now. Never wider than the caller's window."""
    now_ms = int(time.time() * 1000)
    if timeframe is not None and timeframe.to_ms is not None and timeframe.from_ms is not None:
        end = min(timeframe.to_ms, now_ms)
        return {"from": max(end - PROBE_WINDOW_MS, timeframe.from_ms), "to": end}
    span = min(timeframe.relative_ms, PROBE_WINDOW_MS) if timeframe is not None and timeframe.relative_ms else PROBE_WINDOW_MS
    return {"from": now_ms - span, "to": now_ms}


def _probe_problem(probe: dict[str, Any]) -> Problem | None:
    if not probe.get("ran") or probe.get("ok"):
        return None
    error_class = probe.get("class")
    if error_class in XQL_ERROR_CLASSES:
        return Problem(error_class, probe.get("message", ""), field=probe.get("field"))
    return Problem("probe_failed", "The probe failed. XSIAM gave no recognised reason; check the query in the console.")


# --- Rewrites and helpers ---


def _apply_rewrites(stripped: str, rewrites: list[Rewrite], append_limit: bool) -> str | None:
    if not rewrites and not append_limit:
        return None
    corrected = stripped
    last_start = len(stripped) + 1
    for rewrite in sorted(rewrites, key=lambda item: item.start, reverse=True):
        if rewrite.end > last_start:
            continue
        corrected = corrected[: rewrite.start] + rewrite.replacement + corrected[rewrite.end :]
        last_start = rewrite.start
    if append_limit:
        corrected = f"{corrected.rstrip()} | limit {APPENDED_LIMIT}"
    return corrected


def _address_literal(token: Token) -> str | None:
    if token.kind != "string" or token.text.startswith('"""') or "\\" in token.text:
        return None
    try:
        return str(ipaddress.ip_address(token.text[1:-1]))
    except ValueError:
        return None


def _did_you_mean(name: str, candidates: list[str]) -> str | None:
    safe = [candidate for candidate in candidates if SAFE_IDENTIFIER_RE.match(candidate)]
    lowered = {candidate.lower(): candidate for candidate in safe}
    matches = difflib.get_close_matches(name.lower(), list(lowered), n=MAX_SUGGESTIONS, cutoff=0.75)
    if not matches:
        return None
    return "Did you mean: " + ", ".join(lowered[match] for match in matches) + "?"


def _days(milliseconds: int) -> str:
    return f"{round(milliseconds / DAY_MS, 2):g}"
