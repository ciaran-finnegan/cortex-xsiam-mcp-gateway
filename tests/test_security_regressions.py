import json
import time
from types import SimpleNamespace

import httpx
import pytest
from fastmcp.tools.tool import ToolResult
from starlette.datastructures import Headers

from config.config import get_config
from entities.exceptions import (
    PAPIAuthenticationError,
    PAPIClientRequestError,
    PAPIResponseError,
)
from entities.MCPContext import MCPContext
from main import validate_transport_security
from pkg.client import PAPIClient
from service.cortex_mcp import audit_middleware
from usecase import identity
from usecase.audit import AuditExportError
from usecase.builtin_components import issues
from usecase.credential_broker import (
    clear_current_credential_selection,
    reset_current_credential_selection,
    select_xsiam_credentials,
)
from usecase.identity import (
    IdentityAuthenticationError,
    gateway_signature,
    verify_gateway_headers,
)


def _gateway_headers(*, nonce: str, timestamp: str, secret: str) -> Headers:
    values = {
        "X-MCP-Gateway-Principal": "analyst@example.test",
        "X-MCP-Gateway-Groups": "DataReader",
        "X-MCP-Gateway-Roles": "",
        "X-MCP-Gateway-Issuer": "test-gateway",
        "X-MCP-Gateway-Timestamp": timestamp,
        "X-MCP-Gateway-Nonce": nonce,
    }
    values["X-MCP-Gateway-Signature"] = gateway_signature(
        secret=secret,
        issuer=values["X-MCP-Gateway-Issuer"],
        principal=values["X-MCP-Gateway-Principal"],
        groups=values["X-MCP-Gateway-Groups"],
        roles=values["X-MCP-Gateway-Roles"],
        timestamp=timestamp,
        nonce=nonce,
    )
    return Headers(values)


def _ctx(groups=("Security",)):
    state = {}
    return SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(
                auth_headers={"Authorization": "test-key", "X-XDR-AUTH-ID": "test-id"},
                principal_id="analyst@example.test",
                groups=groups,
            )
        ),
        set_state=lambda key, value: state.__setitem__(key, value),
        get_state=lambda key: state.get(key),
    )


def test_signed_gateway_assertion_cannot_be_replayed(monkeypatch):
    secret = "shared-unit-test-secret"
    timestamp = str(int(time.time()))
    headers = _gateway_headers(nonce="unique-replay-nonce", timestamp=timestamp, secret=secret)
    monkeypatch.setattr(get_config(), "gateway_shared_secret", secret)
    monkeypatch.setattr(get_config(), "gateway_allowed_issuers", "test-gateway")

    verify_gateway_headers(headers)
    with pytest.raises(IdentityAuthenticationError, match="already been used"):
        verify_gateway_headers(headers)


def test_gateway_nonce_cache_saturation_fails_closed_without_evicting_live_entries(monkeypatch):
    secret = "bounded-replay-cache-secret"
    timestamp = str(int(time.time()))
    first = _gateway_headers(nonce="cache-first", timestamp=timestamp, secret=secret)
    second = _gateway_headers(nonce="cache-second", timestamp=timestamp, secret=secret)
    monkeypatch.setattr(get_config(), "gateway_shared_secret", secret)
    monkeypatch.setattr(get_config(), "gateway_allowed_issuers", "test-gateway")
    monkeypatch.setattr(get_config(), "gateway_nonce_cache_size", 1)

    with identity._gateway_nonce_lock:
        identity._gateway_nonces.clear()
    try:
        verify_gateway_headers(first)
        with pytest.raises(IdentityAuthenticationError, match="replay cache is full"):
            verify_gateway_headers(second)
        with pytest.raises(IdentityAuthenticationError, match="already been used"):
            verify_gateway_headers(first)
    finally:
        with identity._gateway_nonce_lock:
            identity._gateway_nonces.clear()


def test_credential_broker_uses_explicit_priority_not_claim_order(monkeypatch):
    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", True)
    monkeypatch.setattr(
        get_config(),
        "xsiam_credential_profiles",
        json.dumps(
            {
                "BroadReader": {
                    "priority": 50,
                    "api_key_env": "TEST_BROAD_KEY",
                    "api_key_id_env": "TEST_BROAD_ID",
                },
                "RestrictedReader": {
                    "priority": 10,
                    "api_key_env": "TEST_RESTRICTED_KEY",
                    "api_key_id_env": "TEST_RESTRICTED_ID",
                },
            }
        ),
    )
    monkeypatch.setenv("TEST_BROAD_KEY", "broad-key")
    monkeypatch.setenv("TEST_BROAD_ID", "broad-id")
    monkeypatch.setenv("TEST_RESTRICTED_KEY", "restricted-key")
    monkeypatch.setenv("TEST_RESTRICTED_ID", "restricted-id")

    selection = select_xsiam_credentials(
        MCPContext(
            auth_headers={},
            principal_id="analyst@example.test",
            groups=("BroadReader", "RestrictedReader"),
        ),
        {},
    )

    assert selection.matched_group == "RestrictedReader"
    assert selection.auth_headers["Authorization"] == "restricted-key"
    assert len(selection.api_key_id_sha256) == 64


@pytest.mark.asyncio
async def test_papi_client_reports_malformed_json_as_response_error():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="not-json"))
    async with PAPIClient(
        "https://api.example.test",
        {"Authorization": "test-key", "X-XDR-AUTH-ID": "test-id"},
        transport=transport,
    ) as client:
        with pytest.raises(PAPIResponseError, match="Invalid JSON response"):
            await client.request("GET", "/test")


@pytest.mark.asyncio
async def test_papi_client_never_exposes_upstream_error_body(caplog):
    sensitive_body = 'invalid query: dataset = private_data | filter user = "sensitive-value"'
    transport = httpx.MockTransport(lambda request: httpx.Response(400, text=sensitive_body))

    async with PAPIClient(
        "https://api.example.test",
        {"Authorization": "test-key", "X-XDR-AUTH-ID": "test-id"},
        transport=transport,
    ) as client:
        with pytest.raises(PAPIClientRequestError) as exc_info:
            await client.request("POST", "/xql/start_xql_query/")

    assert "status=400" in str(exc_info.value)
    assert sensitive_body not in str(exc_info.value)
    assert sensitive_body not in caplog.text


@pytest.mark.asyncio
async def test_papi_stream_never_exposes_upstream_error_body(caplog):
    sensitive_body = 'denied export for filter account = "sensitive-value"'
    transport = httpx.MockTransport(lambda request: httpx.Response(403, text=sensitive_body))

    async with PAPIClient(
        "https://api.example.test",
        {"Authorization": "test-key", "X-XDR-AUTH-ID": "test-id"},
        transport=transport,
    ) as client:
        with pytest.raises(PAPIAuthenticationError) as exc_info:
            await client.stream("GET", "/export")

    assert "status=403" in str(exc_info.value)
    assert sensitive_body not in str(exc_info.value)
    assert sensitive_body not in caplog.text


@pytest.mark.asyncio
async def test_raw_xql_requires_privileged_group_and_all_dataset_grant(monkeypatch):
    submitted_queries = []

    async def fake_run(*args, **kwargs):
        submitted_queries.append(args[1])
        assert args[2] == 1
        return {
            "query_id": "query-1",
            "reply": {
                "status": "SUCCESS",
                "results": {
                    "data": [
                        {"event_id": "1", "extra": "removed-by-field-cap"},
                        {"event_id": "2", "extra": "also-removed"},
                    ]
                },
            },
        }

    monkeypatch.setattr(get_config(), "identity_auth_mode", "none")
    monkeypatch.setattr(get_config(), "raw_xql_privileged_groups", "Security")
    monkeypatch.setattr(get_config(), "dataset_query_max_rows", 1)
    monkeypatch.setattr(get_config(), "dataset_query_max_fields", 1)
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Security":["host_inventory"]}')
    monkeypatch.setattr(issues, "run_xql_query", fake_run)

    denied = json.loads(await issues.execute_xql_query(_ctx(), "dataset = host_inventory | limit 1"))
    assert submitted_queries == []
    assert denied["success"] == "false"

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Security":["*"]}')
    allowed = json.loads(await issues.execute_xql_query(_ctx(), "dataset = host_inventory | limit 5000"))
    assert submitted_queries == ["dataset = host_inventory | limit 1"]
    assert allowed["success"] == "true"
    assert allowed["returned"] == 1
    assert len(allowed["rows"][0]) == 1
    assert "reply" not in allowed

    missing_limit = json.loads(await issues.execute_xql_query(_ctx(), "dataset = host_inventory"))
    assert missing_limit["success"] == "false"
    assert "must end with" in missing_limit["error"]
    assert len(submitted_queries) == 1


@pytest.mark.asyncio
async def test_audit_end_event_records_actual_selected_credential(monkeypatch):
    events = []
    outer_token = clear_current_credential_selection()
    monkeypatch.setattr(get_config(), "identity_auth_mode", "none")
    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", False)

    async def capture(event):
        events.append(event)

    async def call_next(*, context):
        select_xsiam_credentials(
            context.fastmcp_context.request_context.lifespan_context,
            {"Authorization": "selected-key", "X-XDR-AUTH-ID": "selected-id"},
        )
        return ToolResult(structured_content={"success": True})

    ctx = _ctx()
    middleware_context = SimpleNamespace(
        message=SimpleNamespace(name="query_dataset", arguments={"dataset": "host_inventory", "limit": 2}),
        fastmcp_context=ctx,
    )
    monkeypatch.setattr(audit_middleware, "emit_audit_event", capture)
    try:
        await audit_middleware.ToolAuditMiddleware().on_call_tool(middleware_context, call_next)
    finally:
        reset_current_credential_selection(outer_token)

    end_event = next(event for event in events if event["phase"] == "end")
    assert end_event["xsiam"]["profile_name"] == "default"
    assert end_event["xsiam"]["api_key_id_sha256"] != "selected-id"
    assert len(end_event["xsiam"]["api_key_id_sha256"]) == 64


@pytest.mark.asyncio
async def test_audit_context_is_restored_when_fail_closed_start_export_fails(monkeypatch):
    outer_token = clear_current_credential_selection()
    select_xsiam_credentials(
        MCPContext(auth_headers={}, principal_id="outer", groups=()),
        {"Authorization": "outer-key", "X-XDR-AUTH-ID": "outer-id"},
    )
    monkeypatch.setattr(get_config(), "identity_auth_mode", "none")
    monkeypatch.setattr(get_config(), "audit_log_emit_start_events", True)

    async def fail_export(event):
        raise AuditExportError("collector unavailable")

    async def call_next(*, context):
        raise AssertionError("tool must not run after fail-closed start export failure")

    monkeypatch.setattr(audit_middleware, "emit_audit_event", fail_export)
    middleware_context = SimpleNamespace(
        message=SimpleNamespace(name="query_dataset", arguments={}),
        fastmcp_context=_ctx(),
    )
    try:
        with pytest.raises(AuditExportError):
            await audit_middleware.ToolAuditMiddleware().on_call_tool(middleware_context, call_next)
        selection = audit_middleware.get_current_credential_selection()
        assert selection is not None
        assert selection.api_key_id_sha256 != "outer-id"
    finally:
        reset_current_credential_selection(outer_token)


def test_http_transport_requires_verified_identity_by_default(monkeypatch):
    monkeypatch.setattr(get_config(), "identity_auth_mode", "none")
    monkeypatch.setattr(get_config(), "allow_unauthenticated_http", False)

    with pytest.raises(ValueError, match="requires verified identity"):
        validate_transport_security("streamable-http")

    validate_transport_security("stdio")
    monkeypatch.setattr(get_config(), "allow_unauthenticated_http", True)
    validate_transport_security("streamable-http")
