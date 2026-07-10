import json
import os
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256

from config.config import get_config
from entities.MCPContext import MCPContext


class CredentialBrokerError(PermissionError):
    """Raised when role-scoped XSIAM credentials cannot be selected."""


@dataclass(frozen=True)
class CredentialSelection:
    auth_headers: dict[str, str]
    profile_name: str
    matched_group: str | None
    api_key_id_sha256: str


_current_selection: ContextVar[CredentialSelection | None] = ContextVar(
    "xsiam_credential_selection",
    default=None,
)


def select_xsiam_credentials(context: MCPContext, fallback_headers: dict[str, str]) -> CredentialSelection:
    config = get_config()
    if not config.xsiam_credential_broker_enabled:
        return _record_selection(CredentialSelection(
            fallback_headers,
            "default",
            None,
            _key_id_hash(fallback_headers),
        ))

    profiles = _parse_profiles(config.xsiam_credential_profiles)
    matching_profiles = sorted(
        (
            (int(profiles[group]["priority"]), group, profiles[group])
            for group in context.groups
            if group in profiles
        ),
        key=lambda item: (item[0], item[1]),
    )
    for _, group, profile in matching_profiles:
        api_key = os.environ.get(str(profile["api_key_env"]), "")
        api_key_id = os.environ.get(str(profile["api_key_id_env"]), "")
        if not api_key or not api_key_id:
            raise CredentialBrokerError(f"XSIAM credential profile for group {group} is not fully configured")
        return _record_selection(CredentialSelection(
            {"Authorization": api_key, "X-XDR-AUTH-ID": api_key_id},
            str(profile.get("profile_name", group)),
            group,
            sha256(api_key_id.encode()).hexdigest(),
        ))

    raise CredentialBrokerError(f"No XSIAM credential profile matches principal {context.principal_id}")


def get_current_credential_selection() -> CredentialSelection | None:
    return _current_selection.get()


def clear_current_credential_selection():
    return _current_selection.set(None)


def reset_current_credential_selection(token) -> None:
    _current_selection.reset(token)


def _record_selection(selection: CredentialSelection) -> CredentialSelection:
    _current_selection.set(selection)
    return selection


def _key_id_hash(headers: dict[str, str]) -> str:
    key_id = headers.get("X-XDR-AUTH-ID", "")
    return sha256(key_id.encode()).hexdigest() if key_id else ""


def _parse_profiles(raw_profiles: str) -> dict[str, dict[str, str | int]]:
    try:
        parsed = json.loads(raw_profiles or "{}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid XSIAM_CREDENTIAL_PROFILES JSON: {e}") from e

    if not isinstance(parsed, dict):
        raise ValueError("XSIAM_CREDENTIAL_PROFILES must be a JSON object mapping groups to profiles")

    profiles: dict[str, dict[str, str | int]] = {}
    for group, profile in parsed.items():
        if not isinstance(profile, dict):
            raise ValueError(f"Credential profile for group {group} must be an object")
        api_key_env = profile.get("api_key_env")
        api_key_id_env = profile.get("api_key_id_env")
        priority = profile.get("priority", 1000)
        if not isinstance(api_key_env, str) or not isinstance(api_key_id_env, str):
            raise ValueError(f"Credential profile for group {group} requires api_key_env and api_key_id_env")
        if not isinstance(priority, int):
            raise ValueError(f"Credential profile priority for group {group} must be an integer")
        profiles[str(group)] = {
            "api_key_env": api_key_env,
            "api_key_id_env": api_key_id_env,
            "profile_name": str(profile.get("profile_name") or group),
            "priority": priority,
        }

    return profiles
