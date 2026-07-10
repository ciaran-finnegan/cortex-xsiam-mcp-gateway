import pytest

from entities.MCPContext import MCPContext
from service.cortex_mcp.audit_middleware import ToolAuditMiddleware
from service.cortex_mcp.server import create_mcp_server
from usecase.audit import create_tool_audit_event, summarize_tool_arguments
from usecase.log_policy import ToolAuthorizationError, ensure_raw_xql_authorized


def test_audit_argument_summary_hashes_query_text_by_default(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "audit_log_include_query_text", False)

    summary = summarize_tool_arguments(
        "search_logs",
        {
            "dataset": "xdr_data",
            "query": "dataset = xdr_data | filter actor_effective_username = \"alice\"",
            "limit": 50,
        },
    )

    assert summary["dataset"] == "xdr_data"
    assert summary["limit"] == 50
    assert "query_sha256" in summary
    assert "query" not in summary


def test_audit_argument_summary_can_include_query_text_when_explicitly_enabled(monkeypatch):
    from config.config import get_config

    query = "dataset = xdr_data | limit 10"
    monkeypatch.setattr(get_config(), "audit_log_include_query_text", True)

    summary = summarize_tool_arguments("execute_xql_query", {"query": query})

    assert summary["query"] == query


def test_raw_xql_authorization_allows_privileged_group(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "raw_xql_privileged_groups", "Security,Admin")
    context = MCPContext(auth_headers={}, principal_id="analyst@example.com", groups=("Security",))

    ensure_raw_xql_authorized(context)


def test_raw_xql_authorization_denies_non_privileged_group(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "raw_xql_privileged_groups", "Security,Admin")
    context = MCPContext(auth_headers={}, principal_id="tier1@example.com", groups=("Tier1",))

    with pytest.raises(ToolAuthorizationError):
        ensure_raw_xql_authorized(context)


def test_mcp_server_registers_audit_middleware():
    server = create_mcp_server("key", "key-id")

    assert any(isinstance(middleware, ToolAuditMiddleware) for middleware in server.middleware)


def test_audit_event_records_nonsecret_credential_profile_only():
    event = create_tool_audit_event(
        tool_name="get_cases",
        phase="start",
        outcome="started",
        principal=MCPContext(
            auth_headers={"X-XDR-AUTH-ID": "sensitive-key-id"},
            principal_id="analyst@example.com",
            groups=("Security",),
        ),
        arguments={},
        credential_summary={"profile_name": "tier1-readonly", "matched_group": "Tier1"},
    )

    assert event["xsiam"] == {"profile_name": "tier1-readonly", "matched_group": "Tier1"}
    assert "sensitive-key-id" not in str(event)


def test_audit_event_hashes_error_text_instead_of_logging_it():
    event = create_tool_audit_event(
        tool_name="query_dataset",
        phase="end",
        outcome="error",
        principal=MCPContext(auth_headers={}, principal_id="analyst@example.com", groups=("Security",)),
        arguments={"dataset": "sample"},
        error=RuntimeError('upstream echoed filter user_name = "sensitive-user"'),
    )

    assert "sensitive-user" not in str(event)
    assert event["error"]["type"] == "RuntimeError"
    assert len(event["error"]["message_sha256"]) == 64
