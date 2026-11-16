import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from starlette.datastructures import Headers

from entities.MCPContext import MCPContext
from service.cortex_mcp.identity_middleware import IdentityMiddleware
from usecase.identity import (
    API_KEY_AUTH_SOURCE,
    ApiKeyRegistryError,
    IdentityAuthenticationError,
    authenticate_http_headers,
    load_api_key_registry,
    mcp_context_from_access_token,
    verify_api_key,
)
from usecase.log_policy import ToolAuthorizationError
from usecase.tool_policy import ensure_tool_authorized

SECRET = "s" * 43
TOKEN = f"xgw_analyst-one.{SECRET}"
OTHER_TOKEN = f"xgw_analyst-two.{'t' * 43}"


def _digest(token: str) -> str:
    return sha256(token.encode()).hexdigest()


def _registry(**overrides) -> str:
    entry = {"sha256": _digest(TOKEN), "principal": "analyst.one", "groups": ["Tier1"]}
    entry.update(overrides)
    return json.dumps(
        {
            "analyst-one": entry,
            "analyst-two": {"sha256": _digest(OTHER_TOKEN), "principal": "analyst.two", "groups": ["Security"]},
        }
    )


def _configure(monkeypatch, registry: str, mode: str = "api_key"):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "identity_auth_mode", mode)
    monkeypatch.setattr(get_config(), "api_keys", registry)


def _fallback_context():
    return MCPContext(auth_headers={"Authorization": "default-key", "X-XDR-AUTH-ID": "default-id"})


def test_api_key_maps_registry_entry_to_mcp_context(monkeypatch):
    _configure(monkeypatch, _registry())

    access_token = verify_api_key(TOKEN)
    context = mcp_context_from_access_token(access_token, _fallback_context())

    assert context.principal_id == "analyst.one"
    assert context.groups == ("Tier1",)
    assert context.auth_source == API_KEY_AUTH_SOURCE
    assert context.tenant_id is None
    # The XSIAM credentials still come from the gateway's own configuration.
    assert context.auth_headers == _fallback_context().auth_headers


def test_api_key_secret_is_not_carried_past_verification(monkeypatch):
    _configure(monkeypatch, _registry())

    access_token = verify_api_key(TOKEN)

    assert SECRET not in access_token.model_dump_json()
    assert access_token.client_id == "analyst-one"


@pytest.mark.parametrize(
    "token",
    [
        f"xgw_analyst-one.{'x' * 43}",  # wrong secret for a known key id
        f"xgw_nobody.{SECRET}",  # unknown key id
        f"xgw_analyst-two.{SECRET}",  # another key's id with this key's secret
        f"analyst-one.{SECRET}",  # no prefix
        f"xgw_analyst-one{SECRET}",  # no separator
        "xgw_analyst-one.short",  # secret too short
        f"xgw_Analyst-One.{SECRET}",  # key id outside the allowed alphabet
        f"xgw_analyst-one.{SECRET}!",  # secret outside the allowed alphabet
        f"xgw_analyst-one.{'s' * 400}",  # over the length bound
        "",
    ],
)
def test_api_key_rejections_share_one_message(monkeypatch, token):
    _configure(monkeypatch, _registry())

    with pytest.raises(IdentityAuthenticationError) as error:
        verify_api_key(token)

    assert str(error.value) == "Invalid API key"


def test_api_key_registry_hash_is_not_a_credential(monkeypatch):
    _configure(monkeypatch, _registry())

    with pytest.raises(IdentityAuthenticationError):
        verify_api_key(f"xgw_analyst-one.{_digest(TOKEN)}")


def test_api_key_disabled_entry_is_rejected(monkeypatch):
    _configure(monkeypatch, _registry(disabled=True))

    with pytest.raises(IdentityAuthenticationError, match="disabled"):
        verify_api_key(TOKEN)


def test_api_key_expires_at_start_of_expiry_date(monkeypatch):
    today = datetime.now(UTC).date()

    _configure(monkeypatch, _registry(expires=today.isoformat()))
    with pytest.raises(IdentityAuthenticationError, match="expired"):
        verify_api_key(TOKEN)

    _configure(monkeypatch, _registry(expires=(today + timedelta(days=1)).isoformat()))
    assert verify_api_key(TOKEN).subject == "analyst.one"


def test_api_key_expiry_is_not_disclosed_for_a_wrong_secret(monkeypatch):
    yesterday = (datetime.now(UTC).date() - timedelta(days=1)).isoformat()
    _configure(monkeypatch, _registry(expires=yesterday, disabled=True))

    with pytest.raises(IdentityAuthenticationError) as error:
        verify_api_key(f"xgw_analyst-one.{'x' * 43}")

    assert str(error.value) == "Invalid API key"


def test_empty_api_key_registry_rejects_every_key(monkeypatch):
    _configure(monkeypatch, "")

    assert load_api_key_registry("") == {}
    with pytest.raises(IdentityAuthenticationError, match="Invalid API key"):
        verify_api_key(TOKEN)


@pytest.mark.parametrize(
    "registry",
    [
        "not json",
        "[]",
        json.dumps({"analyst-one": "nope"}),
        json.dumps({"Bad Id": {"sha256": "a" * 64, "principal": "p", "groups": []}}),
        json.dumps({"analyst-one": {"sha256": "A" * 64, "principal": "p", "groups": []}}),
        json.dumps({"analyst-one": {"sha256": "a" * 63, "principal": "p", "groups": []}}),
        json.dumps({"analyst-one": {"sha256": "a" * 64, "principal": " ", "groups": []}}),
        json.dumps({"analyst-one": {"sha256": "a" * 64, "principal": "p", "groups": "Security"}}),
        json.dumps({"analyst-one": {"sha256": "a" * 64, "principal": "p", "groups": [""]}}),
        json.dumps({"analyst-one": {"sha256": "a" * 64, "principal": "p", "groups": [], "expires": "soon"}}),
        json.dumps({"analyst-one": {"sha256": "a" * 64, "principal": "p", "groups": [], "disabled": "no"}}),
        json.dumps({"analyst-one": {"sha256": "a" * 64, "principal": "p", "groups": [], "group": ["Admin"]}}),
        json.dumps(
            {
                "analyst-one": {"sha256": "a" * 64, "principal": "p", "groups": []},
                "analyst-two": {"sha256": "a" * 64, "principal": "q", "groups": []},
            }
        ),
    ],
)
def test_malformed_api_key_registry_fails_closed(monkeypatch, registry):
    _configure(monkeypatch, registry)

    with pytest.raises(ApiKeyRegistryError) as error:
        load_api_key_registry(registry)
    assert "a" * 63 not in str(error.value)

    with pytest.raises(IdentityAuthenticationError, match="not usable"):
        verify_api_key(TOKEN)


def test_malformed_api_key_registry_stops_the_server_at_start(monkeypatch):
    from main import validate_transport_security

    _configure(monkeypatch, "not json")

    with pytest.raises(ApiKeyRegistryError):
        validate_transport_security("streamable-http")


def test_api_key_groups_ignore_entra_claim_settings(monkeypatch):
    from config.config import get_config

    _configure(monkeypatch, _registry())
    monkeypatch.setattr(get_config(), "entra_groups_claim", "wids")
    monkeypatch.setattr(get_config(), "entra_roles_claim", "key_id")
    monkeypatch.setattr(get_config(), "entra_principal_claims", "key_id")

    context = mcp_context_from_access_token(verify_api_key(TOKEN), _fallback_context())

    assert context.principal_id == "analyst.one"
    assert context.groups == ("Tier1",)


def test_api_key_groups_drive_tool_policy(monkeypatch):
    from config.config import get_config

    _configure(monkeypatch, _registry())
    monkeypatch.setattr(
        get_config(),
        "tool_access_policy",
        json.dumps({"Tier1": ["query_dataset"], "Security": ["*"]}),
    )
    tier1 = mcp_context_from_access_token(verify_api_key(TOKEN), _fallback_context())
    security = mcp_context_from_access_token(verify_api_key(OTHER_TOKEN), _fallback_context())

    ensure_tool_authorized(tier1, "query_dataset")
    with pytest.raises(ToolAuthorizationError):
        ensure_tool_authorized(tier1, "find_datasets")
    ensure_tool_authorized(security, "find_datasets")


@pytest.mark.asyncio
async def test_api_key_mode_requires_a_bearer_token(monkeypatch):
    _configure(monkeypatch, _registry())

    with pytest.raises(IdentityAuthenticationError, match="Missing bearer token"):
        await authenticate_http_headers(Headers({}))
    with pytest.raises(IdentityAuthenticationError, match="Missing bearer token"):
        await authenticate_http_headers(Headers({"Authorization": f"Basic {TOKEN}"}))
    with pytest.raises(IdentityAuthenticationError, match="Missing bearer token"):
        await authenticate_http_headers(Headers({"X-Api-Key": TOKEN}))


@pytest.mark.asyncio
async def test_api_key_mode_ignores_trusted_gateway_headers(monkeypatch):
    from config.config import get_config

    _configure(monkeypatch, _registry())
    monkeypatch.setattr(get_config(), "gateway_shared_secret", "shared-test-secret")

    with pytest.raises(IdentityAuthenticationError, match="Missing bearer token"):
        await authenticate_http_headers(
            Headers({"X-MCP-Gateway-Principal": "admin@example.test", "X-MCP-Gateway-Groups": "Admin"})
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["entra", "gateway", "entra_or_gateway"])
async def test_api_keys_are_not_accepted_in_other_modes(monkeypatch, mode):
    from config.config import get_config

    _configure(monkeypatch, _registry(), mode=mode)
    monkeypatch.setattr(get_config(), "entra_audience", "api://cortex-xsiam-mcp")
    monkeypatch.setattr(get_config(), "entra_jwt_public_key", "unit-test-secret")
    monkeypatch.setattr(get_config(), "entra_jwt_algorithm", "HS256")
    monkeypatch.setattr(get_config(), "gateway_shared_secret", "shared-test-secret")

    with pytest.raises(IdentityAuthenticationError):
        await authenticate_http_headers(Headers({"Authorization": f"Bearer {TOKEN}"}))


@pytest.mark.asyncio
async def test_identity_middleware_passes_a_valid_api_key_and_blocks_an_invalid_one(monkeypatch):
    _configure(monkeypatch, _registry())
    reached = []
    sent = []

    async def app(scope, receive, send):
        reached.append(scope["user"].access_token.subject)

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    middleware = IdentityMiddleware(app)
    path = "/api/v1/stream/mcp"

    await middleware(
        {"type": "http", "path": path, "headers": [(b"authorization", f"Bearer {TOKEN}".encode())]},
        receive,
        send,
    )
    assert reached == ["analyst.one"]
    assert sent == []

    await middleware(
        {"type": "http", "path": path, "headers": [(b"authorization", f"Bearer xgw_analyst-one.{'x' * 43}".encode())]},
        receive,
        send,
    )
    assert reached == ["analyst.one"]
    assert sent[0]["status"] == 401
    assert SECRET.encode() not in sent[1]["body"]
