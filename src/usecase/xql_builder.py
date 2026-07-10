import re

MAX_XQL_RESULT_LIMIT = 1000
DEFAULT_LOG_FIELDS = ["event_id", "event_type", "event_sub_type"]
SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
TERMINAL_LIMIT_RE = re.compile(r"\|\s*limit\s+([0-9]+)\s*$", re.IGNORECASE)


def _validate_identifier(value: str, label: str) -> str:
    if not value or len(value) > 255 or not SAFE_IDENTIFIER_RE.match(value):
        raise ValueError(f"Invalid {label}: {value}")
    return value


def _format_xql_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _build_filter_clause(field: str, operator: str, value) -> str:
    field = _validate_identifier(field, "filter field")
    operator = operator.lower()

    if operator in {"eq", "=", "=="}:
        return f"{field} = {_format_xql_value(value)}"
    if operator in {"neq", "!=", "ne"}:
        return f"{field} != {_format_xql_value(value)}"
    if operator in {"contains", "not_contains"}:
        clause = f'{field} contains {_format_xql_value(value)}'
        return f"not ({clause})" if operator == "not_contains" else clause
    if operator in {"regex", "not_regex"}:
        clause = f"{field} ~= {_format_xql_value(value)}"
        return f"not ({clause})" if operator == "not_regex" else clause
    if operator in {"gte", ">=", "gt", ">", "lte", "<=", "lt", "<"}:
        symbol = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<"}.get(operator, operator)
        return f"{field} {symbol} {_format_xql_value(value)}"
    if operator in {"in", "not_in"}:
        values = value if isinstance(value, list) else [value]
        if not values:
            raise ValueError(f"Filter operator {operator} requires at least one value")
        joined = ", ".join(_format_xql_value(item) for item in values)
        clause = f"{field} in ({joined})"
        return f"not ({clause})" if operator == "not_in" else clause
    if operator == "is_null":
        return f"{field} = null"
    if operator == "is_not_null":
        return f"{field} != null"

    raise ValueError(f"Unsupported filter operator: {operator}")


def build_filter_clause(field: str, operator: str, value=None) -> str:
    """Build one validated XQL filter clause for structured query tools."""
    return _build_filter_clause(field, operator, value)


def format_xql_value(value) -> str:
    """Format a literal value without allowing caller-supplied XQL expressions."""
    return _format_xql_value(value)


def validate_identifier(value: str, label: str) -> str:
    """Validate a dataset, field, or alias identifier used by generated XQL."""
    return _validate_identifier(value, label)


def enforce_terminal_xql_limit(query: str, maximum: int) -> str:
    """Require and clamp a terminal numeric limit on privileged raw XQL."""
    normalized = query.strip()
    match = TERMINAL_LIMIT_RE.search(normalized)
    if not match:
        raise ValueError("Raw XQL must end with a numeric '| limit N' stage")
    requested = int(match.group(1))
    if requested < 1:
        raise ValueError("Raw XQL terminal limit must be at least 1")
    safe_limit = min(requested, max(int(maximum), 1), MAX_XQL_RESULT_LIMIT)
    return normalized[: match.start(1)] + str(safe_limit)


def build_structured_xql(
    dataset: str,
    filters: list[dict] | None = None,
    fields: list[str] | None = None,
    limit: int = 100,
) -> str:
    dataset = _validate_identifier(dataset, "dataset")
    safe_limit = min(max(int(limit), 1), MAX_XQL_RESULT_LIMIT)
    query_parts = [f"dataset = {dataset}"]

    for filter_item in filters or []:
        query_parts.append(
            "| filter "
            + _build_filter_clause(
                filter_item["field"],
                filter_item.get("operator", "eq"),
                filter_item.get("value"),
            )
        )

    selected_fields = fields or DEFAULT_LOG_FIELDS
    if selected_fields:
        safe_fields = [_validate_identifier(field, "field") for field in selected_fields]
        query_parts.append("| fields " + ", ".join(safe_fields))

    query_parts.append(f"| limit {safe_limit}")
    query = " ".join(query_parts)
    from config.config import get_config

    if len(query) > get_config().xql_max_query_chars:
        raise ValueError(f"Generated XQL exceeds the configured {get_config().xql_max_query_chars}-character limit")
    return query
