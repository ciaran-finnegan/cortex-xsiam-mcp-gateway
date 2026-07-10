#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CASES_PATH = ROOT / "tests" / "agent_eval" / "cases.json"
FORBIDDEN_ARGUMENTS = {"query", "natural_language_query", "tenants"}
FILTER_OPERATORS = {
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
}


def load_cases() -> list[dict[str, Any]]:
    return json.loads(CASES_PATH.read_text())


def build_prompt(cases: list[dict[str, Any]]) -> str:
    visible_cases = [
        {key: value for key, value in case.items() if key != "expect"}
        for case in cases
    ]
    return """You are planning MCP tool calls for Cortex XSIAM. Return only the JSON object required by the supplied output schema.

The MCP client agent, not the server, maps plain English to structured calls. For each independent case, choose exactly one next action.

Available tools:
- query_dataset: typed query for one explicit allowed dataset. Rows mode requires fields. Aggregate mode uses metrics, group_by, optional time_bucket, order_by, timeframe, and a small limit.
- discover_log_fields: use when the requested concept has no matching discovered field. Arguments include dataset and optional field_name_contains.
- continue_dataset_query: use only with the opaque cursor from a prior response.
- execute_xql_query: privileged raw-XQL escape hatch. Never use it for these standard-reader cases.

Rules:
- Use only the case's allowed datasets and discovered field names. Never invent a field.
- Prefer aggregates for counts, top values, averages, and trends.
- Use limit 25 or less. Do not try to exhaust all pages.
- Never provide query, natural_language_query, or tenants arguments.
- continue_dataset_query accepts only the supplied opaque cursor; do not add dataset or reconstructed query arguments.
- For a restricted dataset, deny. For an unbounded or vague bulk request, clarify.
- If a standard reader asks for raw XQL but the intent fits allowed discovered fields, preserve the intent with query_dataset rather than denying the request.
- For top-N, sort the metric alias descending and use the requested limit.
- A 24-hour timeframe is {\"relative_ms\": 86400000}.
- Each result must contain id, action, tool, arguments, and a short reason. The evaluation envelope requires every arguments key; set unused keys to null. Use null tool and all-null arguments for clarify or deny.

Cases:
""" + json.dumps(visible_cases, indent=2, sort_keys=True)


def validate_results(cases: list[dict[str, Any]], payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    results = payload.get("results")
    if not isinstance(results, list):
        return ["results must be an array"]
    by_id = {result.get("id"): result for result in results if isinstance(result, dict)}
    if len(results) != len(cases) or len(by_id) != len(cases):
        errors.append(f"expected {len(cases)} unique results, received {len(results)}")

    for case in cases:
        result = by_id.get(case["id"])
        if not isinstance(result, dict):
            errors.append(f"{case['id']}: missing result")
            continue
        errors.extend(_validate_case(case, result))
    return errors


def _validate_case(case: dict[str, Any], result: dict[str, Any]) -> list[str]:
    case_id = case["id"]
    expected = case["expect"]
    arguments = result.get("arguments")
    errors = []
    if result.get("action") != expected["action"]:
        errors.append(f"{case_id}: expected action {expected['action']}, got {result.get('action')}")
    if expected.get("tool") != result.get("tool"):
        errors.append(f"{case_id}: expected tool {expected.get('tool')}, got {result.get('tool')}")
    if not isinstance(arguments, dict):
        return [*errors, f"{case_id}: arguments must be an object"]
    arguments = _compact_arguments(arguments)
    forbidden = FORBIDDEN_ARGUMENTS.intersection(arguments)
    if forbidden:
        errors.append(f"{case_id}: forbidden arguments {sorted(forbidden)}")

    if expected["action"] in {"clarify", "deny"}:
        if arguments:
            errors.append(f"{case_id}: {expected['action']} must not include tool arguments")
        return errors
    if expected["action"] == "continue":
        if arguments != {"cursor": case["cursor"]}:
            errors.append(f"{case_id}: continuation must pass only the supplied opaque cursor")
        return errors

    dataset = arguments.get("dataset")
    if dataset != expected.get("dataset"):
        errors.append(f"{case_id}: expected dataset {expected.get('dataset')}, got {dataset}")
    if dataset not in case["allowed_datasets"]:
        errors.append(f"{case_id}: selected a dataset outside the allowed list")
    if expected["action"] == "discover_fields":
        return errors

    if arguments.get("mode", "rows") != expected.get("mode"):
        errors.append(f"{case_id}: expected mode {expected.get('mode')}, got {arguments.get('mode', 'rows')}")
    limit = arguments.get("limit", 25)
    if not isinstance(limit, int) or limit < 1 or limit > 25:
        errors.append(f"{case_id}: limit must be between 1 and 25")
    if "limit" in expected and limit != expected["limit"]:
        errors.append(f"{case_id}: expected limit {expected['limit']}, got {limit}")

    discovered = set(case["discovered_fields"].get(dataset, []))
    used_fields = _used_fields(arguments)
    invented = used_fields - discovered
    if invented:
        errors.append(f"{case_id}: invented fields {sorted(invented)}")
    required_outputs = set(expected.get("required_output_fields", []))
    if not required_outputs.issubset(set(arguments.get("fields", []))):
        errors.append(f"{case_id}: missing required output fields {sorted(required_outputs)}")
    filter_fields = {item.get("field") for item in arguments.get("filters", []) if isinstance(item, dict)}
    invalid_operators = {
        item.get("operator")
        for item in arguments.get("filters", [])
        if isinstance(item, dict) and item.get("operator") not in FILTER_OPERATORS
    }
    if invalid_operators:
        errors.append(f"{case_id}: invalid filter operators {sorted(invalid_operators)}")
    required_filters = set(expected.get("required_filter_fields", []))
    if not required_filters.issubset(filter_fields):
        errors.append(f"{case_id}: missing required filter fields {sorted(required_filters)}")

    metrics = arguments.get("metrics", [])
    if expected.get("metric") and not any(
        metric.get("function") == expected["metric"]
        and (not expected.get("metric_field") or metric.get("field") == expected["metric_field"])
        for metric in metrics
        if isinstance(metric, dict)
    ):
        errors.append(f"{case_id}: missing expected {expected['metric']} metric")
    if not set(expected.get("group_by", [])).issubset(set(arguments.get("group_by", []))):
        errors.append(f"{case_id}: missing expected group_by fields")
    if expected.get("time_bucket_field") != (arguments.get("time_bucket") or {}).get("field"):
        if expected.get("time_bucket_field"):
            errors.append(f"{case_id}: missing expected time bucket")
    if expected.get("relative_ms") != (arguments.get("timeframe") or {}).get("relative_ms"):
        if expected.get("relative_ms"):
            errors.append(f"{case_id}: missing expected relative timeframe")
    if expected.get("descending_metric_sort"):
        aliases = {metric.get("alias") for metric in metrics if isinstance(metric, dict)}
        if not any(
            item.get("field") in aliases and item.get("direction") == "desc"
            for item in arguments.get("order_by", [])
            if isinstance(item, dict)
        ):
            errors.append(f"{case_id}: top-N query must sort a metric alias descending")
    return errors


def _used_fields(arguments: dict[str, Any]) -> set[str]:
    fields = set(arguments.get("fields", [])) | set(arguments.get("group_by", []))
    fields.update(item.get("field") for item in arguments.get("filters", []) if isinstance(item, dict))
    fields.update(item.get("field") for item in arguments.get("order_by", []) if isinstance(item, dict))
    fields.update(item.get("field") for item in arguments.get("metrics", []) if isinstance(item, dict))
    time_bucket = arguments.get("time_bucket")
    if isinstance(time_bucket, dict):
        fields.add(time_bucket.get("field"))
    metric_aliases = {item.get("alias") for item in arguments.get("metrics", []) if isinstance(item, dict)}
    return {field for field in fields if field and field not in metric_aliases}


def _compact_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in arguments.items()
        if value is not None and value != [] and value != {}
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--emit-prompt", action="store_true")
    group.add_argument("--validate", type=Path)
    args = parser.parse_args()
    cases = load_cases()
    if args.emit_prompt:
        print(build_prompt(cases))
        return 0

    payload = json.loads(args.validate.read_text())
    errors = validate_results(cases, payload)
    if errors:
        print("Agent plan evaluation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"Agent plan evaluation passed: {len(cases)}/{len(cases)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
