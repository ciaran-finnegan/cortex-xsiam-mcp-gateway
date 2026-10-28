"""Classify XSIAM XQL failure messages into a small set of safe, agent-facing classes.

XSIAM error text is never returned verbatim: it can echo query text and tenant details, and it is
an injection path into the agent. A message that matches a known class is replaced by a fixed,
gateway-authored message plus, where the pattern captures one, a field name that passes the
identifier check and integer line and column numbers. Anything else keeps the hashed form.
"""

import re
from contextvars import ContextVar
from typing import Any

from usecase.xql_builder import SAFE_IDENTIFIER_RE
from usecase.xql_docs import problem_docs

XQL_VALIDATION_ERROR = "xql_validation"
UNCLASSIFIED = "unclassified"
XQL_ERROR_CLASSES = ("unknown_field", "unknown_dataset", "syntax_error", "type_mismatch", "timeframe_invalid")
ERROR_DETAIL_KEYS = ("class", "message", "field", "position", "docs", "error_reference_sha256")

_MAX_SCANNED_CHARS = 4000
_MAX_POSITION = 1_000_000
_IDENT = r"(?P<q>['\"`]?)(?P<name>[A-Za-z_][A-Za-z0-9_.]{0,254})(?P=q)"
_MISSING = (
    r"(?:does not exist|doesn't exist|was not found|is not found|not found|is unknown|is not defined"
    r"|cannot be resolved|could not be resolved)"
)
# Words that follow "unknown field" in prose rather than naming the field.
_NOT_A_NAME = frozenset({"a", "an", "the", "in", "of", "for", "from", "is", "name", "named", "or", "and", "on"})

_CLASS_PATTERNS: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = (
    (
        "unknown_field",
        tuple(
            re.compile(pattern, re.IGNORECASE)
            for pattern in (
                rf"\b(?:field|column)\s+{_IDENT}\s+{_MISSING}",
                rf"\b(?:unknown|unrecognized|undefined|no such)\s+(?:field|column)s?\b(?:\s*[:=]?\s*{_IDENT})?",
            )
        ),
    ),
    (
        "unknown_dataset",
        tuple(
            re.compile(pattern, re.IGNORECASE)
            for pattern in (
                rf"\bdataset\s+{_IDENT}\s+{_MISSING}",
                r"\b(?:unknown|no such)\s+dataset\b",
                rf"\bdataset\s+{_MISSING}",
            )
        ),
    ),
    (
        "syntax_error",
        (
            re.compile(
                r"\bsyntax error\b|\bmismatched input\b|\bextraneous input\b|\bno viable alternative\b"
                r"|\bpars(?:e|ing) error\b|\bfailed to parse\b|\bunexpected (?:token|input|character|end of (?:input|query))\b"
                r"|\bmissing '[^']{1,20}' at\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        "type_mismatch",
        (
            re.compile(
                r"\btype mismatch\b|\bincompatible (?:data )?types?\b|\bcan(?:not|'t) (?:be )?compare\b|\bcannot be compared\b"
                r"|\bexpected (?:type|an? (?:string|integer|int|number|boolean|timestamp|array))\b"
                r"|\b(?:wrong|invalid|unsupported) (?:argument |operand )?type\b|\bcannot (?:convert|cast)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    (
        "timeframe_invalid",
        (
            re.compile(
                r"\b(?:invalid|illegal|unsupported|bad)\s+time ?(?:frame|range)\b"
                r"|\btime ?frame\b.{0,60}\b(?:invalid|exceeds?|too (?:long|large)|must|out of range|not supported)\b"
                r"|\brelative_?time\b.{0,40}\b(?:invalid|must|not supported)\b",
                re.IGNORECASE,
            ),
        ),
    ),
)

_POSITION_PATTERNS = (
    re.compile(r"\bline\s+(?P<line>\d{1,7}):(?P<column>\d{1,7})", re.IGNORECASE),
    re.compile(
        r"\bline\s*:?\s*(?P<line>\d{1,7})\s*,?\s*(?:column|col|position|pos|char(?:acter)?)\s*:?\s*(?P<column>\d{1,7})",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:position|pos|column|col|offset|char(?:acter)?)\s*:?\s*(?P<column>\d{1,7})\b", re.IGNORECASE),
)

CLASS_MESSAGES = {
    "unknown_field": (
        "XSIAM rejected the query because a field does not exist in the dataset. "
        "Check field names with discover_log_fields or validate_xql."
    ),
    "unknown_dataset": (
        "XSIAM rejected the query because the dataset does not exist on this tenant. "
        "Check the name with list_log_datasets."
    ),
    "syntax_error": (
        "XSIAM could not parse the query. Check stage order, pipes, quoting and operators; "
        "validate_xql reports common mistakes."
    ),
    "type_mismatch": (
        "XSIAM rejected a value of the wrong type for a field, operator or function. "
        "Check the field type; enum-backed fields may need contains, arrays need array functions."
    ),
    "timeframe_invalid": (
        "XSIAM rejected the timeframe. Pass an absolute window as epoch milliseconds within the configured maximum."
    ),
}

_current_error_class: ContextVar[str | None] = ContextVar("xql_error_class", default=None)


def classify_xql_error(detail: Any) -> dict[str, Any] | None:
    """Return ``{"class", "message", "docs", "field"?, "position"?}`` for a known message, else None."""
    text = _detail_text(detail)
    if not text:
        return None
    for error_class, patterns in _CLASS_PATTERNS:
        for pattern in patterns:
            match = pattern.search(text)
            if match is None:
                continue
            classified: dict[str, Any] = {
                "class": error_class,
                "message": CLASS_MESSAGES[error_class],
                "docs": problem_docs(error_class),
            }
            if error_class == "unknown_field":
                name = _safe_name(match.groupdict().get("name"))
                if name:
                    classified["field"] = name
            if error_class == "syntax_error":
                position = _position(text)
                if position:
                    classified["position"] = position
            return classified
    return None


def xql_error_details(response: dict[str, Any]) -> dict[str, Any]:
    """Return the safe classification and reference keys of an executor failure, for tool responses."""
    return {key: response[key] for key in ERROR_DETAIL_KEYS if key in response}


def get_current_xql_error_class() -> str | None:
    return _current_error_class.get()


def clear_current_xql_error_class():
    return _current_error_class.set(None)


def reset_current_xql_error_class(token) -> None:
    _current_error_class.reset(token)


def record_xql_error_class(error_class: str) -> None:
    """Remember the class of the latest failed query in this tool call for the audit event."""
    _current_error_class.set(error_class if error_class in XQL_ERROR_CLASSES else UNCLASSIFIED)


def _detail_text(detail: Any) -> str:
    if isinstance(detail, str):
        return detail[:_MAX_SCANNED_CHARS]
    parts: list[str] = []
    pending = [detail]
    while pending and sum(len(part) for part in parts) < _MAX_SCANNED_CHARS:
        item = pending.pop(0)
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
    return " ".join(parts)[:_MAX_SCANNED_CHARS]


def _safe_name(name: str | None) -> str | None:
    name = (name or "").rstrip(".")
    if not name or name.lower() in _NOT_A_NAME or not SAFE_IDENTIFIER_RE.match(name):
        return None
    return name


def _position(text: str) -> dict[str, int] | None:
    for pattern in _POSITION_PATTERNS:
        match = pattern.search(text)
        if match is None:
            continue
        position = {key: int(value) for key, value in match.groupdict().items() if value is not None}
        if all(0 <= value < _MAX_POSITION for value in position.values()):
            return position
    return None
