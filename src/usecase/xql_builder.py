import re

MAX_XQL_RESULT_LIMIT = 1000
DEFAULT_LOG_FIELDS = ["event_id", "event_type", "event_sub_type"]
SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def _validate_identifier(value: str, label: str) -> str:
    if not value or not SAFE_IDENTIFIER_RE.match(value):
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
    if operator in {"gte", ">=", "gt", ">", "lte", "<=", "lt", "<"}:
        symbol = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<"}.get(operator, operator)
        return f"{field} {symbol} {_format_xql_value(value)}"
    if operator in {"in", "not_in"}:
        values = value if isinstance(value, list) else [value]
        joined = ", ".join(_format_xql_value(item) for item in values)
        clause = f"{field} in ({joined})"
        return f"not ({clause})" if operator == "not_in" else clause

    raise ValueError(f"Unsupported filter operator: {operator}")


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
    return " ".join(query_parts)
