import ipaddress
import re

MAX_XQL_RESULT_LIMIT = 1000
DEFAULT_LOG_FIELDS = ["event_id", "event_type", "event_sub_type"]
SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


class XQLTranslationError(ValueError):
    """Raised when a natural-language request cannot be safely converted."""


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


def _extract_time_window(text: str) -> dict[str, str] | None:
    match = re.search(r"\blast\s+(\d+)\s*(minute|minutes|hour|hours|day|days)\b", text)
    if not match:
        return None

    amount = int(match.group(1))
    unit = match.group(2)
    suffix = "m" if unit.startswith("minute") else "h" if unit.startswith("hour") else "d"
    return {"relative": f"{amount}{suffix}"}


def translate_log_search_to_xql(
    natural_language_query: str,
    dataset: str | None = None,
    fields: list[str] | None = None,
    limit: int = 100,
) -> dict:
    """
    Conservative local natural-language translation for common SOC log searches.

    This is intentionally template-based. Free-form NL-to-XQL should be handled
    by an approved LLM translation service with policy checks before execution.
    """
    text = natural_language_query.strip()
    if not text:
        raise XQLTranslationError("natural_language_query cannot be empty")

    lower_text = text.lower()
    selected_dataset = dataset or "xdr_data"
    translated_filters: list[dict] = []

    if "issue" in lower_text or "alert" in lower_text:
        translated_filters.append({"field": "event_type", "operator": "contains", "value": "issue"})

    if "failed" in lower_text and any(word in lower_text for word in ["login", "logon", "authentication", "auth"]):
        translated_filters.append({"field": "event_type", "operator": "contains", "value": "authentication"})
        translated_filters.append({"field": "event_sub_type", "operator": "contains", "value": "fail"})
    elif any(word in lower_text for word in ["login", "logon", "authentication", "auth"]):
        translated_filters.append({"field": "event_type", "operator": "contains", "value": "authentication"})

    severity_match = re.search(r"\b(critical|high|medium|low|informational)\b", lower_text)
    if severity_match:
        translated_filters.append({"field": "severity", "operator": "eq", "value": severity_match.group(1)})

    for ip_candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            ipaddress.ip_address(ip_candidate)
        except ValueError:
            continue
        translated_filters.append({"field": "src_ip", "operator": "eq", "value": ip_candidate})

    user_match = re.search(r"\b(?:user|username|account)\s+([A-Za-z0-9._@\\-]+)", text, re.IGNORECASE)
    if user_match:
        translated_filters.append(
            {"field": "actor_effective_username", "operator": "contains", "value": user_match.group(1)}
        )

    host_match = re.search(r"\b(?:host|hostname|endpoint)\s+([A-Za-z0-9._-]+)", text, re.IGNORECASE)
    if host_match:
        translated_filters.append({"field": "agent_hostname", "operator": "contains", "value": host_match.group(1)})

    if not translated_filters:
        raise XQLTranslationError(
            "Could not safely translate the natural-language query. Provide raw XQL or use structured fields such as "
            "dataset, filters, fields, and limit."
        )

    return {
        "query": build_structured_xql(selected_dataset, translated_filters, fields, limit),
        "translation": {
            "mode": "template",
            "source": natural_language_query,
            "dataset": selected_dataset,
            "filters": translated_filters,
            "time_window": _extract_time_window(lower_text),
        },
    }
