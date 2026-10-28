import json
from types import SimpleNamespace

import pytest
from fastmcp.tools.tool import ToolResult

from config.config import get_config
from entities.MCPContext import MCPContext
from service.cortex_mcp import audit_middleware
from usecase import xql_executor
from usecase.audit import create_tool_audit_event
from usecase.builtin_components import datasets, logs
from usecase.dataset_query import QueryTimeframe
from usecase.xql_docs import CORTEX_DOCS_BASE_URL
from usecase.xql_errors import (
    XQL_ERROR_CLASSES,
    classify_xql_error,
    clear_current_xql_error_class,
    get_current_xql_error_class,
    reset_current_xql_error_class,
)

ONE_HOUR = {"relativeTime": 3_600_000}


class SequenceFetcher:
    def __init__(self, responses):
        self.responses = iter(responses)

    async def send_request(self, path, data):
        return next(self.responses)


def _ctx(groups=("Security",)):
    return SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(auth_headers={}, principal_id="analyst@example.test", groups=groups)
        ),
        get_state=lambda key: None,
    )


def _use_fetcher(monkeypatch, responses):
    fetcher = SequenceFetcher(responses)

    async def fake_get_fetcher(ctx):
        return fetcher

    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Field usr_name does not exist in dataset sample_auth_logs", {"class": "unknown_field", "field": "usr_name"}),
        ("Unknown field: 'src_ipp'", {"class": "unknown_field", "field": "src_ipp"}),
        ("column `dest_ip` cannot be resolved", {"class": "unknown_field", "field": "dest_ip"}),
        ("Unknown field in filter stage", {"class": "unknown_field"}),
        ("Dataset sample_auth_logz does not exist", {"class": "unknown_dataset"}),
        ("Unknown dataset requested", {"class": "unknown_dataset"}),
        ("line 1:42 mismatched input '|' expecting <EOF>", {"class": "syntax_error", "position": {"line": 1, "column": 42}}),
        ("Syntax error at position 17", {"class": "syntax_error", "position": {"column": 17}}),
        ("Parse error, line 2, column 5: no viable alternative", {"class": "syntax_error", "position": {"line": 2, "column": 5}}),
        ("Type mismatch: cannot compare STRING with INTEGER", {"class": "type_mismatch"}),
        ("Invalid timeframe: from must be before to", {"class": "timeframe_invalid"}),
        ("The timeframe exceeds the maximum allowed range", {"class": "timeframe_invalid"}),
    ],
)
def test_known_xsiam_messages_map_to_safe_classes(message, expected):
    classified = classify_xql_error(message)

    assert classified is not None
    for key, value in expected.items():
        assert classified[key] == value
    if "field" not in expected:
        assert "field" not in classified
    assert classified["message"] and message not in classified["message"]
    assert classified["docs"].startswith(CORTEX_DOCS_BASE_URL)


@pytest.mark.parametrize(
    "detail",
    [
        'invalid field in dataset = sensitive | filter user = "private"',
        "Internal error while executing the query",
        "Query exceeded the memory limit",
        "",
        None,
        {"code": 500},
    ],
)
def test_unrecognised_messages_are_not_classified(detail):
    assert classify_xql_error(detail) is None


def test_structured_detail_is_scanned_and_unsafe_names_are_dropped():
    assert classify_xql_error({"err_msg": "Query failed", "err_extra": "Field user_id does not exist"}) == {
        "class": "unknown_field",
        "message": classify_xql_error("Unknown field")["message"],
        "docs": classify_xql_error("Unknown field")["docs"],
        "field": "user_id",
    }
    assert "field" not in classify_xql_error('Unknown field: "$(curl evil)"')
    assert "field" not in classify_xql_error("Unknown field: the requested name")


@pytest.mark.asyncio
async def test_executor_returns_class_field_and_hash_without_upstream_text(monkeypatch):
    upstream = 'Field usr_name does not exist; query was dataset = sample_auth_logs | filter usr_name = "private-value"'
    _use_fetcher(monkeypatch, [{"reply": "query-1"}, {"reply": {"status": "FAILED", "error_message": upstream}}])
    token = clear_current_xql_error_class()
    try:
        response = await xql_executor.run_xql_query(
            None, "dataset = sample_auth_logs | limit 1", 1, timeframe=ONE_HOUR, poll_interval_seconds=0
        )
        recorded = get_current_xql_error_class()
    finally:
        reset_current_xql_error_class(token)

    assert response["error"] == "xql_validation"
    assert response["class"] == "unknown_field"
    assert response["field"] == "usr_name"
    assert response["xsiam_status"] == "FAILED"
    assert len(response["error_reference_sha256"]) == 64
    assert "private-value" not in json.dumps(response)
    assert recorded == "unknown_field"


@pytest.mark.asyncio
async def test_executor_keeps_the_hashed_form_for_an_unrecognised_message(monkeypatch):
    upstream = "Internal error 7f3a while scanning partition for dataset = sample_auth_logs"
    _use_fetcher(monkeypatch, [{"reply": {"status": "ERROR", "error": upstream}}])
    token = clear_current_xql_error_class()
    try:
        response = await xql_executor.run_xql_query(None, "dataset = sample_auth_logs | limit 1", 1, timeframe=ONE_HOUR)
        recorded = get_current_xql_error_class()
    finally:
        reset_current_xql_error_class(token)

    assert response["error"] == "XQL query failed"
    assert "class" not in response
    assert len(response["error_reference_sha256"]) == 64
    assert upstream not in json.dumps(response)
    assert recorded == "unclassified"


@pytest.mark.asyncio
async def test_typed_tools_pass_the_class_through_to_the_agent(monkeypatch):
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"DataReader":["sample_auth_logs"]}')
    failure = {
        "query_id": "query-9",
        "error": "xql_validation",
        "class": "unknown_field",
        "field": "usr_name",
        "message": "XSIAM rejected the query because a field does not exist in the dataset.",
        "docs": f"{CORTEX_DOCS_BASE_URL}/xql-schema-reference",
        "error_reference_sha256": "b" * 64,
    }

    async def fake_run(ctx, query, result_limit, **kwargs):
        return dict(failure)

    monkeypatch.setattr(datasets, "run_xql_query", fake_run)
    monkeypatch.setattr(logs, "run_xql_query", fake_run)

    typed = await datasets.query_dataset(
        _ctx(("DataReader",)),
        dataset="sample_auth_logs",
        fields=["usr_name"],
        timeframe=QueryTimeframe(relative_ms=60_000),
    )
    compat = json.loads(
        await logs.search_logs(
            _ctx(("DataReader",)), dataset="sample_auth_logs", fields=["usr_name"], timeframe=ONE_HOUR
        )
    )

    for response in (typed, compat):
        assert response["error"] == "xql_validation"
        assert response["class"] == "unknown_field"
        assert response["field"] == "usr_name"
        assert response["error_reference_sha256"] == "b" * 64


def test_audit_event_records_the_error_class():
    principal = MCPContext(auth_headers={}, principal_id="analyst@example.test", groups=("Security",))
    event = create_tool_audit_event(
        tool_name="execute_xql_query",
        phase="end",
        outcome="error",
        principal=principal,
        xql_error_class="unknown_field",
    )
    quiet = create_tool_audit_event(tool_name="get_cases", phase="end", outcome="success", principal=principal)

    assert event["xql_error_class"] == "unknown_field"
    assert "xql_error_class" not in quiet
    assert set(XQL_ERROR_CLASSES) == {"unknown_field", "unknown_dataset", "syntax_error", "type_mismatch", "timeframe_invalid"}


@pytest.mark.asyncio
async def test_audit_middleware_adds_the_class_of_a_failed_query_and_resets_it(monkeypatch):
    events = []
    monkeypatch.setattr(get_config(), "identity_auth_mode", "none")
    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", False)
    _use_fetcher(monkeypatch, [{"reply": {"status": "FAILED", "error_message": "Unknown dataset requested"}}])

    async def capture(event):
        events.append(event)

    async def call_next(*, context):
        response = await xql_executor.run_xql_query(None, "dataset = sample_missing | limit 1", 1, timeframe=ONE_HOUR)
        return ToolResult(structured_content={"success": False, **response})

    monkeypatch.setattr(audit_middleware, "emit_audit_event", capture)
    middleware_context = SimpleNamespace(
        message=SimpleNamespace(name="execute_xql_query", arguments={"query": "dataset = sample_missing | limit 1"}),
        fastmcp_context=_ctx(),
    )
    await audit_middleware.ToolAuditMiddleware().on_call_tool(middleware_context, call_next)

    end_event = next(event for event in events if event["phase"] == "end")
    assert end_event["xql_error_class"] == "unknown_dataset"
    assert get_current_xql_error_class() is None
