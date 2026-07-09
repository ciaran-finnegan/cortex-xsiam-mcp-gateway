from typing import Any

from entities.MCPContext import MCPContext
from usecase.log_policy import ALL_DATASETS, authorize_dataset
from usecase.xql_builder import _validate_identifier

MAX_DISCOVERY_SAMPLE_SIZE = 100
DEFAULT_DISCOVERY_SAMPLE_SIZE = 25
MAX_DISCOVERY_DATASET_COUNT = 100
DEFAULT_DISCOVERY_DATASET_COUNT = 50
MAX_DISCOVERY_FIELD_COUNT = 200
DEFAULT_DISCOVERY_FIELD_COUNT = 75


def build_field_discovery_xql(dataset: str, sample_size: int = DEFAULT_DISCOVERY_SAMPLE_SIZE) -> str:
    safe_dataset = _validate_identifier(dataset, "dataset")
    safe_limit = min(max(int(sample_size), 1), MAX_DISCOVERY_SAMPLE_SIZE)
    return f"dataset = {safe_dataset} | limit {safe_limit}"


def normalize_dataset_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = {_normalize_key(key): value for key, value in record.items()}
    dataset_name = normalized.get("dataset_name") or normalized.get("name")
    if isinstance(dataset_name, str):
        dataset_name = dataset_name.strip()
    return {
        "dataset_name": dataset_name,
        "type": normalized.get("type"),
        "log_update_type": normalized.get("log_update_type"),
        "default_query_target": normalized.get("default_query_target"),
    }


def filter_authorized_dataset_records(
    records: list[dict[str, Any]],
    context: MCPContext,
    name_contains: str | None = None,
    max_datasets: int = DEFAULT_DISCOVERY_DATASET_COUNT,
) -> tuple[list[dict[str, Any]], bool]:
    safe_limit = min(max(int(max_datasets), 1), MAX_DISCOVERY_DATASET_COUNT)
    name_filter = name_contains.lower() if name_contains else None
    allowed_records = []
    for record in records:
        dataset_name = record.get("dataset_name")
        if not isinstance(dataset_name, str) or not dataset_name:
            continue
        if name_filter and name_filter not in dataset_name.lower():
            continue
        decision = authorize_dataset(context, dataset_name)
        if decision.allowed:
            allowed_records.append({**record, "dataset_policy": decision.__dict__})
    return allowed_records[:safe_limit], len(allowed_records) > safe_limit


def policy_dataset_records(
    context: MCPContext,
    name_contains: str | None = None,
    max_datasets: int = DEFAULT_DISCOVERY_DATASET_COUNT,
) -> tuple[list[dict[str, Any]], bool]:
    decision = authorize_dataset(context, ALL_DATASETS)
    safe_limit = min(max(int(max_datasets), 1), MAX_DISCOVERY_DATASET_COUNT)
    name_filter = name_contains.lower() if name_contains else None
    allowed = [
        dataset
        for dataset in sorted(set(decision.allowed_datasets))
        if not name_filter or name_filter in dataset.lower()
    ]
    if ALL_DATASETS in allowed:
        return [
            {"dataset_name": ALL_DATASETS, "dataset_policy": {"allowed": True, "reason": "all datasets allowed"}}
        ], False
    records = [
        {
            "dataset_name": dataset,
            "dataset_policy": authorize_dataset(context, dataset).__dict__,
        }
        for dataset in allowed
    ]
    return records[:safe_limit], len(records) > safe_limit


def extract_xql_rows(response_data: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    reply = response_data.get("reply")
    if isinstance(reply, dict):
        candidates.extend(
            [
                reply.get("results"),
                reply.get("data"),
                reply.get("records"),
                reply.get("events"),
            ]
        )
    candidates.extend(
        [
            response_data.get("results"),
            response_data.get("data"),
            response_data.get("records"),
            response_data.get("events"),
        ]
    )

    for candidate in candidates:
        rows = _coerce_rows(candidate)
        if rows:
            return rows

    return []


def infer_field_catalog(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields: dict[str, dict[str, Any]] = {}
    for row in rows:
        for field_name, value in row.items():
            field = fields.setdefault(
                field_name,
                {
                    "name": field_name,
                    "observed_count": 0,
                    "types": set(),
                },
            )
            field["observed_count"] += 1
            field["types"].add(_infer_value_type(value))

    catalog = []
    for field in fields.values():
        types = sorted(field["types"])
        inferred_type = types[0] if len(types) == 1 else "mixed"
        item = {
            "name": field["name"],
            "type": inferred_type,
            "observed_count": field["observed_count"],
        }
        if len(types) > 1:
            item["observed_types"] = types
        catalog.append(item)

    return sorted(catalog, key=lambda item: item["name"])


def filter_field_catalog(
    fields: list[dict[str, Any]],
    field_name_contains: str | None = None,
    max_fields: int = DEFAULT_DISCOVERY_FIELD_COUNT,
) -> tuple[list[dict[str, Any]], bool]:
    safe_limit = min(max(int(max_fields), 1), MAX_DISCOVERY_FIELD_COUNT)
    name_filter = field_name_contains.lower() if field_name_contains else None
    filtered = [
        field
        for field in fields
        if not name_filter or name_filter in str(field.get("name", "")).lower()
    ]
    return filtered[:safe_limit], len(filtered) > safe_limit


def _normalize_key(key: str) -> str:
    return key.strip().lower().replace(" ", "_")


def _coerce_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        for nested_key in ("results", "data", "records", "events"):
            nested_rows = _coerce_rows(value.get(nested_key))
            if nested_rows:
                return nested_rows
    return []


def _infer_value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__
