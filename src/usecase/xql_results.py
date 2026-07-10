import json
from typing import Any

from config.config import get_config


def bound_result_rows(
    rows: list[dict[str, Any]],
    *,
    hidden_fields: tuple[str, ...] = (),
    allowed_fields: tuple[str, ...] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    config = get_config()
    hidden = set(hidden_fields)
    output: list[dict[str, Any]] = []
    bytes_used = 0
    cell_truncations = 0
    field_truncations = 0
    budget_exhausted = False

    for row in rows:
        if allowed_fields is None:
            visible_items = [(key, value) for key, value in row.items() if key not in hidden]
        else:
            visible_items = [(key, row[key]) for key in allowed_fields if key in row and key not in hidden]
        if len(visible_items) > config.dataset_query_max_fields:
            visible_items = visible_items[: config.dataset_query_max_fields]
            field_truncations += 1
        bounded_row = {}
        for key, value in visible_items:
            bounded_value, truncated = _bound_value(value, config.dataset_query_max_cell_chars)
            bounded_row[key] = bounded_value
            cell_truncations += truncated
        encoded_size = len(json.dumps(bounded_row, ensure_ascii=False, default=str, separators=(",", ":")).encode())
        if bytes_used + encoded_size > config.dataset_query_max_response_bytes:
            budget_exhausted = True
            break
        output.append(bounded_row)
        bytes_used += encoded_size

    return output, {
        "bytes": bytes_used,
        "cell_truncations": cell_truncations,
        "field_truncations": field_truncations,
        "response_budget_exhausted": budget_exhausted,
    }


def result_metadata(response_data: dict[str, Any]) -> dict[str, Any]:
    reply = response_data.get("reply")
    if not isinstance(reply, dict):
        return {}
    metadata: dict[str, Any] = {}
    for key in ("number_of_results", "remaining_quota", "query_cost"):
        if key in reply:
            metadata[key] = reply[key]
    return metadata


def _bound_value(value: Any, max_chars: int) -> tuple[Any, int]:
    if isinstance(value, str):
        if len(value) <= max_chars:
            return value, 0
        return value[:max_chars] + "...<truncated>", 1
    if isinstance(value, list):
        bounded = []
        count = 0
        for item in value[:50]:
            result, truncated = _bound_value(item, max_chars)
            bounded.append(result)
            count += truncated
        if len(value) > 50:
            bounded.append("...<truncated>")
            count += 1
        return bounded, count
    if isinstance(value, dict):
        bounded = {}
        count = 0
        for index, (key, item) in enumerate(value.items()):
            if index >= 50:
                bounded["_truncated"] = True
                count += 1
                break
            result, truncated = _bound_value(item, max_chars)
            bounded[key] = result
            count += truncated
        return bounded, count
    return value, 0
