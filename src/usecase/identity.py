import hmac
import json
import logging
import re
import time
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, date, datetime
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
from usecase.engagement import apply_engagement

logger = logging.getLogger("cortex_xsiam_mcp.identity")

VALID_IDENTITY_AUTH_MODES = {"none", "entra", "gateway", "entra_or_gateway", "api_key"}
API_KEY_AUTH_SOURCE = "api-key"
API_KEY_PREFIX = "xgw_"
API_KEY_MIN_SECRET_CHARS = 32
API_KEY_MAX_TOKEN_CHARS = 256
_API_KEY_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{2,63}")
_API_KEY_SECRET_PATTERN = re.compile(r"[A-Za-z0-9_-]+")
_API_KEY_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_API_KEY_ENTRY_FIELDS = {"sha256", "principal", "groups", "expires", "disabled", "created", "note"}
# Compared against when the key id is unknown, so a miss costs the same as a wrong secret.
_API_KEY_DUMMY_SHA256 = sha256(b"cortex-xsiam-mcp-gateway:no-such-api-key").hexdigest()
_gateway_nonces: OrderedDict[tuple[str, str, str], int] = OrderedDict()
_gateway_nonce_lock = Lock()
_service_principal: ContextVar[MCPContext | None] = ContextVar("service_principal", default=None)

class IdentityAuthenticationError(PermissionError):
    """Raised when incoming MCP identity cannot be verified."""


class ApiKeyRegistryError(ValueError):
    """Raised when MCP_API_KEYS is not a valid registry. The message never includes a hash."""


@dataclass(frozen=True)
class ApiKeyEntry:
    key_id: str
    sha256: str
    principal: str
    groups: tuple[str, ...]
    expires: date | None = None
    disabled: bool = False


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


@contextmanager
def service_principal(context: MCPContext) -> Iterator[MCPContext]:
    """Run in-process background work, such as the learner, as a configured service principal.

    Only code in the same process can set this; no MCP request input reaches it. Dataset
    policy, tool policy, the credential broker and audit still apply to the principal.
    """
    token = _service_principal.set(context)
    try:
        yield context
    finally:
        _service_principal.reset(token)


def resolve_mcp_context(ctx: Any | None) -> MCPContext:
    service = _service_principal.get()
    if service is not None:
        return service
    fallback = _lifespan_context(ctx) or default_mcp_context()
    access_token = get_access_token()
    if access_token:
        return apply_engagement(mcp_context_from_access_token(access_token, fallback))

    if _identity_mode() != "none":
        raise IdentityAuthenticationError("Incoming MCP identity is required but was not verified")

    return apply_engagement(fallback)


async def authenticate_http_headers(headers: Headers | dict[str, str]) -> AccessToken | None:
    mode = _identity_mode()
    if mode == "none":
        return None

    headers = Headers(headers) if isinstance(headers, dict) else headers
    errors = []

    if mode == "api_key":
        bearer = _extract_bearer(headers)
        if not bearer:
            raise IdentityAuthenticationError("Missing bearer token")
        return verify_api_key(bearer)

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


def verify_api_key(token: str) -> AccessToken:
    """Verify a static client API key against the hashed registry in MCP_API_KEYS.

    The token is `xgw_<key_id>.<secret>`. Only its SHA-256 is configured, so the registry
    alone cannot be replayed as a credential. Every rejection before the hash matches uses
    one message, so a caller cannot tell a wrong key id from a wrong secret.
    """
    try:
        registry = load_api_key_registry(get_config().api_keys)
    except ApiKeyRegistryError as e:
        logger.error("MCP_API_KEYS is invalid, rejecting every API key: %s", e)
        raise IdentityAuthenticationError("API key registry is not usable") from e

    key_id = _api_key_id_from_token(token)
    entry = registry.get(key_id) if key_id else None
    presented = sha256(token.encode("utf-8", "surrogatepass")).hexdigest()
    matches = hmac.compare_digest(presented, entry.sha256 if entry else _API_KEY_DUMMY_SHA256)
    if entry is None or not matches:
        logger.warning("API key rejected: key_id=%s", key_id if entry else "unknown")
        raise IdentityAuthenticationError("Invalid API key")
    if entry.disabled:
        logger.warning("API key rejected: key_id=%s is disabled", entry.key_id)
        raise IdentityAuthenticationError("API key is disabled")
    today = datetime.now(UTC).date()
    if entry.expires is not None and today >= entry.expires:
        logger.warning("API key rejected: key_id=%s expired on %s", entry.key_id, entry.expires.isoformat())
        raise IdentityAuthenticationError("API key has expired")

    return AccessToken(
        # Never carry the presented secret past this point.
        token=API_KEY_AUTH_SOURCE,
        client_id=entry.key_id,
        scopes=[],
        expires_at=_epoch_at_utc_midnight(entry.expires) if entry.expires else None,
        subject=entry.principal,
        claims={
            "auth_source": API_KEY_AUTH_SOURCE,
            "key_id": entry.key_id,
            "principal": entry.principal,
            "groups": list(entry.groups),
        },
    )


def load_api_key_registry(raw: str) -> dict[str, ApiKeyEntry]:
    """Parse and validate MCP_API_KEYS. An empty value is an empty registry: every key is rejected."""
    return dict(_parse_api_key_registry(raw or ""))


@lru_cache(maxsize=4)
def _parse_api_key_registry(raw: str) -> tuple[tuple[str, ApiKeyEntry], ...]:
    if not raw.strip():
        return ()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ApiKeyRegistryError("MCP_API_KEYS is not valid JSON") from e
    if not isinstance(data, dict):
        raise ApiKeyRegistryError("MCP_API_KEYS must be a JSON object of key id to entry")

    entries: list[tuple[str, ApiKeyEntry]] = []
    seen_hashes: set[str] = set()
    for key_id, value in data.items():
        if not _API_KEY_ID_PATTERN.fullmatch(key_id):
            raise ApiKeyRegistryError("MCP_API_KEYS has a key id that is not 3-64 chars of a-z, 0-9 and hyphen")
        if not isinstance(value, dict):
            raise ApiKeyRegistryError(f"MCP_API_KEYS entry {key_id} must be an object")
        unknown = sorted(set(value) - _API_KEY_ENTRY_FIELDS)
        if unknown:
            raise ApiKeyRegistryError(f"MCP_API_KEYS entry {key_id} has unknown fields: {', '.join(unknown)}")
        digest = value.get("sha256")
        if not isinstance(digest, str) or not _API_KEY_SHA256_PATTERN.fullmatch(digest):
            raise ApiKeyRegistryError(f"MCP_API_KEYS entry {key_id} needs sha256 as 64 lowercase hex chars")
        if digest in seen_hashes:
            raise ApiKeyRegistryError(f"MCP_API_KEYS entry {key_id} repeats another entry's sha256")
        seen_hashes.add(digest)
        principal = value.get("principal")
        if not isinstance(principal, str) or not principal.strip() or principal != principal.strip():
            raise ApiKeyRegistryError(f"MCP_API_KEYS entry {key_id} needs a non-empty principal")
        groups = value.get("groups", [])
        if not isinstance(groups, list) or any(not isinstance(g, str) or not g.strip() for g in groups):
            raise ApiKeyRegistryError(f"MCP_API_KEYS entry {key_id} needs groups as a list of names")
        disabled = value.get("disabled", False)
        if not isinstance(disabled, bool):
            raise ApiKeyRegistryError(f"MCP_API_KEYS entry {key_id} needs disabled as true or false")
        expires_raw = value.get("expires")
        expires = None
        if expires_raw is not None:
            try:
                expires = date.fromisoformat(expires_raw) if isinstance(expires_raw, str) else None
            except ValueError:
                expires = None
            if expires is None:
                raise ApiKeyRegistryError(f"MCP_API_KEYS entry {key_id} needs expires as YYYY-MM-DD")
        entries.append(
            (
                key_id,
                ApiKeyEntry(
                    key_id=key_id,
                    sha256=digest,
                    principal=principal,
                    groups=tuple(dict.fromkeys(g.strip() for g in groups)),
                    expires=expires,
                    disabled=disabled,
                ),
            )
        )
    return tuple(entries)


def _api_key_id_from_token(token: str) -> str | None:
    if len(token) > API_KEY_MAX_TOKEN_CHARS or not token.startswith(API_KEY_PREFIX):
        return None
    key_id, separator, secret = token[len(API_KEY_PREFIX) :].partition(".")
    if not separator or not _API_KEY_ID_PATTERN.fullmatch(key_id):
        return None
    if len(secret) < API_KEY_MIN_SECRET_CHARS or not _API_KEY_SECRET_PATTERN.fullmatch(secret):
        return None
    return key_id


def _epoch_at_utc_midnight(day: date) -> int:
    return int(datetime(day.year, day.month, day.day, tzinfo=UTC).timestamp())


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
    if claims.get("auth_source") == API_KEY_AUTH_SOURCE:
        # Built by verify_api_key from the operator's registry. Read it directly so the
        # Entra claim-name settings cannot change who an API key is or what it may do.
        return MCPContext(
            auth_headers=fallback.auth_headers,
            principal_id=str(access_token.subject),
            groups=tuple(_claim_values(claims, "groups")),
            auth_source=API_KEY_AUTH_SOURCE,
            tenant_id=None,
        )
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
