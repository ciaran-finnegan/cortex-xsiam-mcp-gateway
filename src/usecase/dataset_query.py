import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, ConfigDict, Field, model_validator

from config.config import get_config
from entities.MCPContext import MCPContext
from usecase.xql_builder import (
    MAX_XQL_RESULT_LIMIT,
    build_filter_clause,
    format_xql_value,
    validate_identifier,
)

QueryMode = Literal["rows", "aggregate"]
FilterLogic = Literal["and", "or"]
FilterValueType = Literal["literal", "timestamp_ms"]
FilterOperator = Literal[
    "eq",
    "neq",
    "contains",
    "not_contains",
    "regex",
    "not_regex",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "is_null",
    "is_not_null",
]
MetricFunction = Literal["count", "count_distinct", "sum", "avg", "min", "max"]
SortDirection = Literal["asc", "desc"]
CursorValueType = Literal["auto", "literal", "timestamp_ms"]
TimeBucketUnit = Literal["m", "h", "d"]


class QueryFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(description="Discovered field name to filter.")
    operator: FilterOperator = Field(description="Structured comparison operator.")
    value: Any | None = Field(default=None, description="Literal filter value. Omit for null operators.")
    value_type: FilterValueType = Field(
        default="literal",
        description="Use timestamp_ms when a numeric epoch-millisecond value targets an XQL TIMESTAMP field.",
    )

    @model_validator(mode="after")
    def validate_value(self):
        if self.operator in {"is_null", "is_not_null"}:
            if self.value is not None:
                raise ValueError(f"{self.operator} does not accept a value")
        elif self.value is None:
            raise ValueError(f"{self.operator} requires a value")
        if self.operator in {"in", "not_in"} and not isinstance(self.value, list):
            raise ValueError(f"{self.operator} requires a list value")
        if self.value_type == "timestamp_ms":
            if self.operator not in {"eq", "neq", "gt", "gte", "lt", "lte"}:
                raise ValueError("timestamp_ms supports only comparison operators")
            if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
                raise ValueError("timestamp_ms requires an epoch-millisecond number")
        return self


class QueryMetric(BaseModel):
    model_config = ConfigDict(extra="forbid")

    function: MetricFunction = Field(description="Allowlisted XQL aggregate function.")
    alias: str = Field(description="Field name returned for this metric.")
    field: str | None = Field(default=None, description="Discovered numeric or categorical field. Optional for count.")

    @model_validator(mode="after")
    def validate_field(self):
        if self.function != "count" and not self.field:
            raise ValueError(f"{self.function} requires a field")
        return self


class QuerySort(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(description="Returned field or aggregate alias used for deterministic sorting.")
    direction: SortDirection = Field(default="asc", description="Ascending or descending order.")
    value_type: CursorValueType = Field(
        default="auto",
        description=(
            "How continuation values are represented in XQL. Auto treats _time as an epoch-millisecond timestamp; "
            "use timestamp_ms for other XQL TIMESTAMP fields."
        ),
    )


class QueryTimeBucket(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(default="_time", description="Timestamp field to bin before aggregation.")
    size: int = Field(default=1, ge=1, le=1000, description="Positive bucket size.")
    unit: TimeBucketUnit = Field(default="h", description="Minute, hour, or day bucket unit.")


class QueryTimeframe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relative_ms: int | None = Field(default=None, gt=0, description="Lookback duration in milliseconds.")
    from_ms: int | None = Field(default=None, ge=0, description="Absolute start epoch in milliseconds.")
    to_ms: int | None = Field(default=None, ge=0, description="Absolute end epoch in milliseconds.")

    @model_validator(mode="after")
    def validate_shape(self):
        relative = self.relative_ms is not None
        absolute = self.from_ms is not None or self.to_ms is not None
        if relative == absolute:
            raise ValueError("Use either relative_ms or both from_ms and to_ms")
        if absolute and (self.from_ms is None or self.to_ms is None):
            raise ValueError("Absolute timeframe requires from_ms and to_ms")
        if absolute and self.from_ms >= self.to_ms:
            raise ValueError("from_ms must be less than to_ms")

        max_span = get_config().dataset_query_max_timeframe_ms
        span = self.relative_ms if relative else self.to_ms - self.from_ms
        if max_span > 0 and span > max_span:
            raise ValueError(f"Timeframe exceeds configured maximum of {max_span} milliseconds")
        return self

    def to_api(self) -> dict[str, int]:
        if self.relative_ms is not None:
            return {"relativeTime": self.relative_ms}
        return {"from": self.from_ms, "to": self.to_ms}


class DatasetQueryPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset: str
    mode: QueryMode = "rows"
    fields: list[str] = Field(default_factory=list)
    filters: list[QueryFilter] = Field(default_factory=list)
    filter_logic: FilterLogic = "and"
    metrics: list[QueryMetric] = Field(default_factory=list)
    group_by: list[str] = Field(default_factory=list)
    time_bucket: QueryTimeBucket | None = None
    order_by: list[QuerySort] = Field(default_factory=list)
    timeframe: QueryTimeframe | None = None
    limit: int = 25
    enable_continuation: bool = False


@dataclass(frozen=True)
class CompiledDatasetQuery:
    xql: str
    result_limit: int
    page_limit: int
    hidden_fields: tuple[str, ...] = ()


class QueryCursorError(ValueError):
    """Raised when a dataset continuation cursor is invalid or no longer authorized."""


def build_dataset_xql(
    plan: DatasetQueryPlan,
    *,
    seek_values: list[Any] | None = None,
) -> CompiledDatasetQuery:
    config = get_config()
    dataset = validate_identifier(plan.dataset, "dataset")
    maximum_page_size = (
        MAX_XQL_RESULT_LIMIT - 1
        if plan.mode == "rows" and plan.enable_continuation
        else MAX_XQL_RESULT_LIMIT
    )
    safe_limit = min(
        max(int(plan.limit), 1),
        config.dataset_query_max_rows,
        maximum_page_size,
    )
    query_parts = [f"dataset = {dataset}"]

    if len(plan.filters) > config.dataset_query_max_filters:
        raise ValueError(f"At most {config.dataset_query_max_filters} filters are allowed")
    filter_clauses = [_query_filter_clause(item) for item in plan.filters]
    if filter_clauses:
        joiner = f" {plan.filter_logic} "
        query_parts.append("| filter " + joiner.join(f"({clause})" for clause in filter_clauses))

    if seek_values is not None:
        query_parts.append("| filter " + _build_seek_clause(plan.order_by, seek_values))

    if plan.time_bucket:
        bucket_field = validate_identifier(plan.time_bucket.field, "time bucket field")
        query_parts.append(f"| bin {bucket_field} span = {plan.time_bucket.size}{plan.time_bucket.unit}")

    hidden_fields: list[str] = []
    if plan.mode == "rows":
        if not plan.fields:
            raise ValueError("Row queries require an explicit non-empty fields list")
        if plan.metrics or plan.group_by or plan.time_bucket:
            raise ValueError("Row queries cannot include metrics, group_by, or time_bucket")
        if len(plan.fields) > config.dataset_query_max_fields:
            raise ValueError(f"At most {config.dataset_query_max_fields} fields are allowed")
        selected_fields = [validate_identifier(field, "field") for field in plan.fields]
        _validate_order_by(plan.order_by)
        for sort_item in plan.order_by:
            sort_field = validate_identifier(sort_item.field, "sort field")
            if sort_field not in selected_fields:
                selected_fields.append(sort_field)
                hidden_fields.append(sort_field)
        if plan.order_by:
            query_parts.append("| sort " + ", ".join(f"{item.direction} {item.field}" for item in plan.order_by))
        query_parts.append("| fields " + ", ".join(selected_fields))
    else:
        if plan.fields:
            raise ValueError("Aggregate queries use metrics and group_by instead of fields")
        if not plan.metrics:
            raise ValueError("Aggregate queries require at least one metric")
        if len(plan.metrics) > config.dataset_query_max_metrics:
            raise ValueError(f"At most {config.dataset_query_max_metrics} metrics are allowed")
        if len(plan.group_by) > config.dataset_query_max_group_fields:
            raise ValueError(f"At most {config.dataset_query_max_group_fields} group fields are allowed")
        group_fields = [validate_identifier(field, "group field") for field in plan.group_by]
        if plan.time_bucket:
            bucket_field = validate_identifier(plan.time_bucket.field, "time bucket field")
            if bucket_field not in group_fields:
                group_fields.insert(0, bucket_field)
        metric_clauses = [_metric_clause(metric) for metric in plan.metrics]
        comp = "| comp " + ", ".join(metric_clauses)
        if group_fields:
            comp += " by " + ", ".join(group_fields)
        query_parts.append(comp)
        _validate_order_by(plan.order_by)
        allowed_sort_fields = {*group_fields, *(metric.alias for metric in plan.metrics)}
        for sort_item in plan.order_by:
            if sort_item.field not in allowed_sort_fields:
                raise ValueError(f"Aggregate sort field must be a group field or metric alias: {sort_item.field}")
        if plan.order_by:
            query_parts.append("| sort " + ", ".join(f"{item.direction} {item.field}" for item in plan.order_by))

    fetch_limit = safe_limit + 1 if plan.mode == "rows" and plan.enable_continuation else safe_limit
    query_parts.append(f"| limit {fetch_limit}")
    xql = " ".join(query_parts)
    if len(xql) > config.xql_max_query_chars:
        raise ValueError(f"Generated XQL exceeds the configured {config.xql_max_query_chars}-character limit")
    return CompiledDatasetQuery(
        xql=xql,
        result_limit=fetch_limit,
        page_limit=safe_limit,
        hidden_fields=tuple(hidden_fields),
    )


def encode_query_cursor(plan: DatasetQueryPlan, principal: MCPContext, last_values: list[Any]) -> str:
    if not plan.enable_continuation or not plan.order_by:
        raise QueryCursorError("Continuation requires enable_continuation=true and deterministic order_by fields")
    payload = {
        "version": 1,
        "principal_id": principal.principal_id,
        "tenant_id": principal.tenant_id,
        "auth_source": principal.auth_source,
        "groups_hash": _groups_hash(principal.groups),
        "policy_hash": _policy_hash(),
        "plan": plan.model_dump(mode="json"),
        "last_values": last_values,
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode()
    return _fernet().encrypt(encoded).decode()


def decode_query_cursor(cursor: str, principal: MCPContext) -> tuple[DatasetQueryPlan, list[Any]]:
    try:
        decoded = _fernet().decrypt(cursor.encode(), ttl=get_config().dataset_query_cursor_ttl_seconds)
        payload = json.loads(decoded)
    except (InvalidToken, ValueError, TypeError, json.JSONDecodeError) as e:
        raise QueryCursorError("Continuation cursor is invalid or expired") from e

    if payload.get("version") != 1:
        raise QueryCursorError("Unsupported continuation cursor version")
    if payload.get("principal_id") != principal.principal_id:
        raise QueryCursorError("Continuation cursor belongs to a different principal")
    if payload.get("tenant_id") != principal.tenant_id or payload.get("auth_source") != principal.auth_source:
        raise QueryCursorError("Continuation cursor identity context has changed")
    if payload.get("groups_hash") != _groups_hash(principal.groups):
        raise QueryCursorError("Continuation cursor groups have changed")
    if payload.get("policy_hash") != _policy_hash():
        raise QueryCursorError("Continuation cursor policy has changed")

    try:
        plan = DatasetQueryPlan.model_validate(payload["plan"])
        last_values = payload["last_values"]
    except (KeyError, TypeError, ValueError) as e:
        raise QueryCursorError("Continuation cursor payload is incomplete") from e
    if not isinstance(last_values, list) or len(last_values) != len(plan.order_by):
        raise QueryCursorError("Continuation cursor sort values are invalid")
    return plan, last_values


def query_hash(xql: str) -> str:
    return hashlib.sha256(xql.encode()).hexdigest()


def _metric_clause(metric: QueryMetric) -> str:
    alias = validate_identifier(metric.alias, "metric alias")
    if metric.function == "count" and not metric.field:
        return f"count() as {alias}"
    field = validate_identifier(metric.field or "", "metric field")
    return f"{metric.function}({field}) as {alias}"


def _query_filter_clause(query_filter: QueryFilter) -> str:
    if query_filter.value_type == "literal":
        return build_filter_clause(query_filter.field, query_filter.operator, query_filter.value)
    field = validate_identifier(query_filter.field, "filter field")
    symbols = {"eq": "=", "neq": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
    value = int(query_filter.value)
    return f'{field} {symbols[query_filter.operator]} to_timestamp({value}, "MILLIS")'


def _validate_order_by(order_by: list[QuerySort]) -> None:
    if len(order_by) > 2:
        raise ValueError("At most two deterministic sort fields are allowed")
    for item in order_by:
        validate_identifier(item.field, "sort field")


def _build_seek_clause(order_by: list[QuerySort], seek_values: list[Any]) -> str:
    if not order_by or len(order_by) != len(seek_values):
        raise ValueError("Continuation requires one value for every sort field")
    branches = []
    for index, sort_item in enumerate(order_by):
        terms = [
            f"{order_by[prefix].field} = {_format_seek_value(order_by[prefix], seek_values[prefix])}"
            for prefix in range(index)
        ]
        comparator = ">" if sort_item.direction == "asc" else "<"
        terms.append(f"{sort_item.field} {comparator} {_format_seek_value(sort_item, seek_values[index])}")
        branches.append("(" + " and ".join(terms) + ")")
    return "(" + " or ".join(branches) + ")"


def _format_seek_value(sort_item: QuerySort, value: Any) -> str:
    is_timestamp = sort_item.value_type == "timestamp_ms" or (
        sort_item.value_type == "auto" and sort_item.field == "_time"
    )
    if not is_timestamp:
        return format_xql_value(value)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Timestamp continuation field {sort_item.field} requires an epoch-millisecond number")
    return f'to_timestamp({int(value)}, "MILLIS")'


def _fernet() -> Fernet:
    secret = get_config().dataset_query_cursor_secret
    if not secret:
        raise QueryCursorError("Continuation is disabled because DATASET_QUERY_CURSOR_SECRET is not configured")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def _groups_hash(groups: tuple[str, ...]) -> str:
    return hashlib.sha256(json.dumps(sorted(groups), separators=(",", ":")).encode()).hexdigest()


def _policy_hash() -> str:
    return hashlib.sha256(get_config().log_search_dataset_policy.encode()).hexdigest()
