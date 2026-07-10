import hmac
import time
from collections import OrderedDict
from functools import lru_cache
from hashlib import sha256
from threading import Lock
from typing import Any

from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.dependencies import get_access_token
from starlette.datastructures import Headers

from config.config import get_config
from entities.MCPContext import MCPContext

VALID_IDENTITY_AUTH_MODES = {"none", "entra", "gateway", "entra_or_gateway"}
_gateway_nonces: OrderedDict[tuple[str, str, str], int] = OrderedDict()
_gateway_nonce_lock = Lock()

class IdentityAuthenticationError(PermissionError):
    """Raised when incoming MCP identity cannot be verified."""


def parse_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def parse_scopes(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.replace(" ", ",").split(",") if item.strip())


def default_mcp_context() -> MCPContext:
    config = get_config()
    return MCPContext(
        auth_headers={},
        principal_id=config.log_search_default_principal_id,
        groups=parse_csv(config.log_search_default_groups),
    )


def resolve_mcp_context(ctx: Any | None) -> MCPContext:
    fallback = _lifespan_context(ctx) or default_mcp_context()
    access_token = get_access_token()
    if access_token:
        return mcp_context_from_access_token(access_token, fallback)

    if _identity_mode() != "none":
        raise IdentityAuthenticationError("Incoming MCP identity is required but was not verified")

    return fallback


async def authenticate_http_headers(headers: Headers | dict[str, str]) -> AccessToken | None:
    mode = _identity_mode()
    if mode == "none":
        return None

    headers = Headers(headers) if isinstance(headers, dict) else headers
    errors = []

    if mode in {"entra", "entra_or_gateway"}:
        bearer = _extract_bearer(headers)
        if bearer:
            try:
                return await verify_entra_bearer(bearer)
            except IdentityAuthenticationError as e:
                errors.append(str(e))
        elif mode == "entra":
            errors.append("Missing bearer token")

    if mode in {"gateway", "entra_or_gateway"}:
        if _has_gateway_headers(headers):
            try:
                return verify_gateway_headers(headers)
            except IdentityAuthenticationError as e:
                errors.append(str(e))
        elif mode == "gateway":
            errors.append("Missing trusted gateway identity headers")

    detail = "; ".join(errors) if errors else f"No supported identity credential for mode {mode}"
    raise IdentityAuthenticationError(detail)


async def verify_entra_bearer(token: str) -> AccessToken:
    verifier = _get_entra_verifier()
    access_token = await verifier.verify_token(token)
    if not access_token:
        raise IdentityAuthenticationError("Invalid Entra bearer token")
    claims = dict(access_token.claims or {})
    claims["auth_source"] = "entra"
    access_token.claims = claims
    return access_token


def verify_gateway_headers(headers: Headers) -> AccessToken:
    config = get_config()
    secret = config.gateway_shared_secret
    if not secret:
        raise IdentityAuthenticationError("MCP_GATEWAY_SHARED_SECRET is required for gateway identity mode")

    principal = _required_header(headers, config.gateway_principal_header)
    groups_raw = headers.get(config.gateway_groups_header, "")
    roles_raw = headers.get(config.gateway_roles_header, "")
    issuer = _required_header(headers, config.gateway_issuer_header)
    timestamp_raw = _required_header(headers, config.gateway_timestamp_header)
    nonce = _required_header(headers, config.gateway_nonce_header)
    signature = _required_header(headers, config.gateway_signature_header)

    allowed_issuers = parse_csv(config.gateway_allowed_issuers)
    if allowed_issuers and issuer not in allowed_issuers:
        raise IdentityAuthenticationError("Gateway issuer is not trusted")

    try:
        timestamp = int(timestamp_raw)
    except ValueError as e:
        raise IdentityAuthenticationError("Gateway timestamp must be a Unix epoch integer") from e

    if abs(int(time.time()) - timestamp) > config.gateway_max_clock_skew_seconds:
        raise IdentityAuthenticationError("Gateway identity assertion is outside the allowed clock skew")

    expected = gateway_signature(
        secret=secret,
        issuer=issuer,
        principal=principal,
        groups=groups_raw,
        roles=roles_raw,
        timestamp=timestamp_raw,
        nonce=nonce,
    )
    if not hmac.compare_digest(expected, signature):
        raise IdentityAuthenticationError("Gateway identity signature is invalid")
    _consume_gateway_nonce(issuer, principal, nonce, timestamp)

    groups = parse_csv(groups_raw)
    roles = parse_csv(roles_raw)
    claims = {
        "auth_source": "trusted-gateway",
        "iss": issuer,
        "preferred_username": principal,
        "groups": list(groups),
        "roles": list(roles),
    }
    return AccessToken(
        token="trusted-gateway",
        client_id=issuer,
        scopes=[],
        expires_at=timestamp + config.gateway_max_clock_skew_seconds,
        subject=principal,
        claims=claims,
    )


def gateway_signature(
    *,
    secret: str,
    issuer: str,
    principal: str,
    groups: str,
    roles: str,
    timestamp: str,
    nonce: str,
) -> str:
    canonical = "\n".join([issuer, principal, groups, roles, timestamp, nonce])
    return hmac.new(secret.encode(), canonical.encode(), sha256).hexdigest()


def _consume_gateway_nonce(issuer: str, principal: str, nonce: str, timestamp: int) -> None:
    config = get_config()
    now = int(time.time())
    key = (issuer, principal, nonce)
    expiry = timestamp + config.gateway_max_clock_skew_seconds
    with _gateway_nonce_lock:
        expired = [cache_key for cache_key, cache_expiry in _gateway_nonces.items() if cache_expiry < now]
        for cache_key in expired:
            _gateway_nonces.pop(cache_key, None)
        if key in _gateway_nonces:
            raise IdentityAuthenticationError("Gateway identity assertion nonce has already been used")
        max_size = max(config.gateway_nonce_cache_size, 1)
        if len(_gateway_nonces) >= max_size:
            raise IdentityAuthenticationError("Gateway identity assertion replay cache is full")
        _gateway_nonces[key] = expiry


def mcp_context_from_access_token(access_token: AccessToken, fallback: MCPContext) -> MCPContext:
    config = get_config()
    claims = dict(access_token.claims or {})
    principal_id = _first_claim(claims, parse_csv(config.entra_principal_claims)) or access_token.subject
    if not principal_id:
        principal_id = access_token.client_id

    groups = _claim_values(claims, config.entra_groups_claim)
    roles = _claim_values(claims, config.entra_roles_claim)
    auth_source = str(claims.get("auth_source") or "entra")
    tenant_id = _first_claim(claims, ("tid", "tenant_id"))

    return MCPContext(
        auth_headers=fallback.auth_headers,
        principal_id=str(principal_id),
        groups=tuple(dict.fromkeys([*groups, *roles])),
        auth_source=auth_source,
        tenant_id=str(tenant_id) if tenant_id else None,
    )


def _get_entra_verifier() -> JWTVerifier:
    config = get_config()
    audience = config.entra_audience
    if not audience:
        raise IdentityAuthenticationError("ENTRA_AUDIENCE is required for Entra identity mode")

    issuer = config.entra_issuer or _issuer_from_tenant(config.entra_tenant_id)
    jwks_uri = config.entra_jwks_uri or _jwks_uri_from_tenant(config.entra_tenant_id)
    public_key = config.entra_jwt_public_key
    if not public_key and not jwks_uri:
        raise IdentityAuthenticationError("ENTRA_TENANT_ID, ENTRA_JWKS_URI, or ENTRA_JWT_PUBLIC_KEY is required")

    return _build_entra_verifier(
        public_key=public_key,
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=audience,
        algorithm=config.entra_jwt_algorithm,
        required_scopes=config.entra_required_scopes,
    )


@lru_cache(maxsize=8)
def _build_entra_verifier(
    *,
    public_key: str,
    jwks_uri: str,
    issuer: str,
    audience: str,
    algorithm: str,
    required_scopes: str,
) -> JWTVerifier:
    kwargs: dict[str, Any] = {
        "issuer": issuer or None,
        "audience": audience,
        "algorithm": algorithm,
        "required_scopes": list(parse_scopes(required_scopes)) or None,
    }
    if public_key:
        kwargs["public_key"] = public_key
    else:
        kwargs["jwks_uri"] = jwks_uri

    return JWTVerifier(**kwargs)


def _identity_mode() -> str:
    mode = get_config().identity_auth_mode.strip().lower()
    if mode not in VALID_IDENTITY_AUTH_MODES:
        raise IdentityAuthenticationError(f"Invalid MCP_IDENTITY_AUTH_MODE: {mode}")
    return mode


def _lifespan_context(ctx: Any | None) -> MCPContext | None:
    request_context = getattr(ctx, "request_context", None)
    lifespan_context = getattr(request_context, "lifespan_context", None)
    return lifespan_context if isinstance(lifespan_context, MCPContext) else None


def _extract_bearer(headers: Headers) -> str | None:
    authorization = headers.get("authorization")
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    return authorization[7:].strip()


def _has_gateway_headers(headers: Headers) -> bool:
    config = get_config()
    return bool(headers.get(config.gateway_principal_header) or headers.get(config.gateway_signature_header))


def _required_header(headers: Headers, name: str) -> str:
    value = headers.get(name)
    if not value:
        raise IdentityAuthenticationError(f"Missing required gateway identity header: {name}")
    return value


def _issuer_from_tenant(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/v2.0" if tenant_id else ""


def _jwks_uri_from_tenant(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys" if tenant_id else ""


def _first_claim(claims: dict[str, Any], names: tuple[str, ...]) -> str | None:
    for name in names:
        value = claims.get(name)
        if isinstance(value, str) and value:
            return value
    return None


def _claim_values(claims: dict[str, Any], name: str) -> list[str]:
    value = claims.get(name)
    if isinstance(value, str):
        return list(parse_csv(value))
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []
