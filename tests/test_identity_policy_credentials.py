import json
import time
from types import SimpleNamespace

import pytest
from authlib.jose import JsonWebToken
from starlette.datastructures import Headers

from entities.MCPContext import MCPContext
from service.cortex_mcp.identity_middleware import IdentityMiddleware
from usecase.credential_broker import CredentialBrokerError, select_xsiam_credentials
from usecase.fetcher import get_fetcher
from usecase.identity import (
    IdentityAuthenticationError,
    authenticate_http_headers,
    gateway_signature,
    mcp_context_from_access_token,
    verify_gateway_headers,
)
from usecase.log_policy import ToolAuthorizationError
from usecase.tool_policy import ensure_tool_authorized


def _token(claims: dict, secret: str = "unit-test-secret") -> str:
    encoded = JsonWebToken(["HS256"]).encode({"alg": "HS256"}, claims, secret)
    return encoded.decode()


def _fallback_context():
    return MCPContext(auth_headers={"Authorization": "default-key", "X-XDR-AUTH-ID": "default-id"})


@pytest.mark.asyncio
async def test_entra_bearer_maps_claims_to_mcp_context(monkeypatch):
    from config.config import get_config

    now = int(time.time())
    monkeypatch.setattr(get_config(), "identity_auth_mode", "entra")
    monkeypatch.setattr(get_config(), "entra_jwt_public_key", "unit-test-secret")
    monkeypatch.setattr(get_config(), "entra_jwt_algorithm", "HS256")
    monkeypatch.setattr(get_config(), "entra_issuer", "https://login.example.test/tenant/v2.0")
    monkeypatch.setattr(get_config(), "entra_audience", "api://xsiam-mcp")
    monkeypatch.setattr(get_config(), "entra_required_scopes", "xsiam.search")

    access_token = await authenticate_http_headers(
        {
            "authorization": "Bearer "
            + _token(
                {
                    "iss": "https://login.example.test/tenant/v2.0",
                    "aud": "api://xsiam-mcp",
                    "exp": now + 300,
                    "scp": "xsiam.search",
                    "preferred_username": "analyst@example.test",
                    "groups": ["Tier1"],
                    "roles": ["IncidentResponder"],
                    "tid": "tenant-id",
                    "sub": "subject-id",
                }
            )
        }
    )

    context = mcp_context_from_access_token(access_token, _fallback_context())

    assert context.principal_id == "analyst@example.test"
    assert context.groups == ("Tier1", "IncidentResponder")
    assert context.auth_source == "entra"
    assert context.tenant_id == "tenant-id"
    assert context.auth_headers["X-XDR-AUTH-ID"] == "default-id"


@pytest.mark.asyncio
async def test_entra_bearer_rejects_wrong_audience(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "identity_auth_mode", "entra")
    monkeypatch.setattr(get_config(), "entra_jwt_public_key", "unit-test-secret")
    monkeypatch.setattr(get_config(), "entra_jwt_algorithm", "HS256")
    monkeypatch.setattr(get_config(), "entra_issuer", "https://login.example.test/tenant/v2.0")
    monkeypatch.setattr(get_config(), "entra_audience", "api://xsiam-mcp")

    with pytest.raises(IdentityAuthenticationError):
        await authenticate_http_headers(
            {
                "authorization": "Bearer "
                + _token(
                    {
                        "iss": "https://login.example.test/tenant/v2.0",
                        "aud": "api://wrong-audience",
                        "exp": int(time.time()) + 300,
                        "sub": "subject-id",
                    }
                )
            }
        )


def test_gateway_headers_validate_signed_identity(monkeypatch):
    from config.config import get_config

    timestamp = str(int(time.time()))
    secret = "shared-test-secret"
    signature = gateway_signature(
        secret=secret,
        issuer="portkey",
        principal="analyst@example.test",
        groups="Tier1,CloudTeam",
        roles="IncidentResponder",
        timestamp=timestamp,
        nonce="nonce-1",
    )
    monkeypatch.setattr(get_config(), "gateway_shared_secret", secret)
    monkeypatch.setattr(get_config(), "gateway_allowed_issuers", "portkey,litellm")

    access_token = verify_gateway_headers(
        Headers(
            {
                "X-MCP-Gateway-Principal": "analyst@example.test",
                "X-MCP-Gateway-Groups": "Tier1,CloudTeam",
                "X-MCP-Gateway-Roles": "IncidentResponder",
                "X-MCP-Gateway-Issuer": "portkey",
                "X-MCP-Gateway-Timestamp": timestamp,
                "X-MCP-Gateway-Nonce": "nonce-1",
                "X-MCP-Gateway-Signature": signature,
            }
        )
    )

    context = mcp_context_from_access_token(access_token, _fallback_context())

    assert context.principal_id == "analyst@example.test"
    assert context.groups == ("Tier1", "CloudTeam", "IncidentResponder")
    assert context.auth_source == "trusted-gateway"


def test_gateway_headers_reject_tampered_identity(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "gateway_shared_secret", "shared-test-secret")
    monkeypatch.setattr(get_config(), "gateway_allowed_issuers", "portkey")

    with pytest.raises(IdentityAuthenticationError):
        verify_gateway_headers(
            Headers(
                {
                    "X-MCP-Gateway-Principal": "analyst@example.test",
                    "X-MCP-Gateway-Groups": "Admin",
                    "X-MCP-Gateway-Issuer": "portkey",
                    "X-MCP-Gateway-Timestamp": str(int(time.time())),
                    "X-MCP-Gateway-Nonce": "nonce-1",
                    "X-MCP-Gateway-Signature": "bad-signature",
                }
            )
        )


def test_tool_policy_allows_group_tool_and_denies_other_tool(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(
        get_config(),
        "tool_access_policy",
        '{"Tier1":["search_logs","list_log_datasets"],"Security":["*"]}',
    )

    context = MCPContext(auth_headers={}, principal_id="tier1@example.test", groups=("Tier1",))

    decision = ensure_tool_authorized(context, "search_logs")
    assert decision.allowed is True
    assert decision.matched_group == "Tier1"

    with pytest.raises(ToolAuthorizationError):
        ensure_tool_authorized(context, "get_tenant_info")


def test_credential_broker_selects_preprovisioned_group_profile(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", True)
    monkeypatch.setattr(
        get_config(),
        "xsiam_credential_profiles",
        json.dumps(
            {
                "Tier1": {
                    "profile_name": "tier1-readonly",
                    "api_key_env": "UNIT_TEST_TIER1_XSIAM_KEY",
                    "api_key_id_env": "UNIT_TEST_TIER1_XSIAM_KEY_ID",
                }
            }
        ),
    )
    monkeypatch.setenv("UNIT_TEST_TIER1_XSIAM_KEY", "profile-key")
    monkeypatch.setenv("UNIT_TEST_TIER1_XSIAM_KEY_ID", "profile-key-id")

    selection = select_xsiam_credentials(
        MCPContext(auth_headers={}, principal_id="tier1@example.test", groups=("Tier1",)),
        {"Authorization": "default-key", "X-XDR-AUTH-ID": "default-id"},
    )

    assert selection.profile_name == "tier1-readonly"
    assert selection.matched_group == "Tier1"
    assert selection.auth_headers == {"Authorization": "profile-key", "X-XDR-AUTH-ID": "profile-key-id"}


def test_credential_broker_fails_closed_when_enabled_without_matching_profile(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", True)
    monkeypatch.setattr(get_config(), "xsiam_credential_profiles", "{}")

    with pytest.raises(CredentialBrokerError):
        select_xsiam_credentials(
            MCPContext(auth_headers={}, principal_id="tier1@example.test", groups=("Tier1",)),
            {"Authorization": "default-key", "X-XDR-AUTH-ID": "default-id"},
        )


@pytest.mark.asyncio
async def test_fetcher_records_selected_credential_profile_for_audit(monkeypatch):
    from config.config import get_config

    state = {}

    def set_state(key, value):
        state[key] = value

    monkeypatch.setattr(get_config(), "papi_url_env_key", "https://api-unit-test.example")
    monkeypatch.setattr(get_config(), "identity_auth_mode", "none")
    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", True)
    monkeypatch.setattr(
        get_config(),
        "xsiam_credential_profiles",
        json.dumps(
            {
                "Tier1": {
                    "profile_name": "tier1-readonly",
                    "api_key_env": "UNIT_TEST_TIER1_XSIAM_KEY",
                    "api_key_id_env": "UNIT_TEST_TIER1_XSIAM_KEY_ID",
                }
            }
        ),
    )
    monkeypatch.setenv("UNIT_TEST_TIER1_XSIAM_KEY", "profile-key")
    monkeypatch.setenv("UNIT_TEST_TIER1_XSIAM_KEY_ID", "profile-key-id")

    ctx = SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(
                auth_headers={"Authorization": "default-key", "X-XDR-AUTH-ID": "default-id"},
                principal_id="tier1@example.test",
                groups=("Tier1",),
            )
        ),
        set_state=set_state,
    )

    fetcher = await get_fetcher(ctx)

    assert fetcher.api_key == "profile-key"
    assert fetcher.api_key_id == "profile-key-id"
    assert state["xsiam_credential_profile"] == {
        "profile_name": "tier1-readonly",
        "matched_group": "Tier1",
    }


@pytest.mark.asyncio
async def test_identity_middleware_requires_identity_for_mcp_paths(monkeypatch):
    from config.config import get_config

    sent = []

    async def app(scope, receive, send):
        raise AssertionError("unauthenticated MCP path must not reach downstream app")

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    monkeypatch.setattr(get_config(), "identity_auth_mode", "entra")
    middleware = IdentityMiddleware(app)

    await middleware({"type": "http", "path": "/api/v1/stream/mcp", "headers": []}, receive, send)

    assert sent[0]["status"] == 401


@pytest.mark.asyncio
async def test_identity_middleware_allows_health_check_without_identity(monkeypatch):
    from config.config import get_config

    reached = {"value": False}

    async def app(scope, receive, send):
        reached["value"] = True

    async def send(message):
        return None

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    monkeypatch.setattr(get_config(), "identity_auth_mode", "entra")
    middleware = IdentityMiddleware(app)

    await middleware({"type": "http", "path": "/ping", "headers": []}, receive, send)

    assert reached["value"] is True
