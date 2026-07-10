import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("agent_evaluator", ROOT / "scripts" / "evaluate_agent_plans.py")
agent_evaluator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(agent_evaluator)


def test_agent_evaluator_accepts_minimal_compliant_reference_plans():
    cases = agent_evaluator.load_cases()
    results = []
    for case in cases:
        expected = case["expect"]
        arguments = _reference_arguments(case)
        results.append(
            {
                "id": case["id"],
                "action": expected["action"],
                "tool": expected.get("tool"),
                "arguments": arguments,
                "reason": "Reference plan",
            }
        )

    assert agent_evaluator.validate_results(cases, {"results": results}) == []


def test_agent_prompt_does_not_leak_expected_results():
    prompt = agent_evaluator.build_prompt(agent_evaluator.load_cases())

    assert '"expect"' not in prompt
    assert '"required_filter_fields"' not in prompt


def test_agent_evaluator_rejects_raw_xql_injection_and_invented_fields():
    case = next(case for case in agent_evaluator.load_cases() if case["id"] == "inventory_rows")
    result = {
        "id": case["id"],
        "action": "query",
        "tool": "query_dataset",
        "arguments": {
            "dataset": "asset_inventory",
            "fields": ["invented_secret"],
            "filters": [],
            "query": "dataset = unrestricted",
        },
        "reason": "Unsafe plan",
    }

    errors = agent_evaluator._validate_case(case, result)
    assert any("forbidden arguments" in error for error in errors)
    assert any("invented fields" in error for error in errors)


def test_agent_evaluator_rejects_xql_operator_in_typed_filter():
    case = next(case for case in agent_evaluator.load_cases() if case["id"] == "raw_xql_nonprivileged")
    result = {
        "id": case["id"],
        "action": "query",
        "tool": "query_dataset",
        "arguments": {
            "dataset": "authentication_events",
            "mode": "rows",
            "fields": ["event_id", "result"],
            "filters": [{"field": "result", "operator": "=", "value": "failed"}],
            "limit": 10,
        },
        "reason": "Wrong operator vocabulary",
    }

    errors = agent_evaluator._validate_case(case, result)
    assert any("invalid filter operators" in error for error in errors)


def _reference_arguments(case):
    expected = case["expect"]
    if expected["action"] in {"clarify", "deny"}:
        return {}
    if expected["action"] == "continue":
        return {"cursor": case["cursor"]}
    if expected["action"] == "discover_fields":
        return {"dataset": expected["dataset"], "field_name_contains": "cost"}

    arguments = {"dataset": expected["dataset"], "mode": expected["mode"], "limit": expected.get("limit", 10)}
    if expected["mode"] == "rows":
        fields = list(expected.get("required_output_fields", []))
        fields.extend(field for field in expected.get("required_filter_fields", []) if field not in fields)
        arguments["fields"] = fields
        arguments["filters"] = [
            {"field": field, "operator": "eq", "value": "expected"}
            for field in expected.get("required_filter_fields", [])
        ]
        return arguments

    alias = "result_value"
    metric = {"function": expected["metric"], "alias": alias}
    if expected.get("metric_field"):
        metric["field"] = expected["metric_field"]
    arguments["metrics"] = [metric]
    arguments["group_by"] = expected.get("group_by", [])
    if expected.get("time_bucket_field"):
        arguments["time_bucket"] = {"field": expected["time_bucket_field"], "size": 1, "unit": "h"}
    if expected.get("relative_ms"):
        arguments["timeframe"] = {"relative_ms": expected["relative_ms"]}
    if expected.get("descending_metric_sort"):
        arguments["order_by"] = [{"field": alias, "direction": "desc"}]
    return arguments
