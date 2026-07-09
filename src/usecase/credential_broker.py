import json
import os
from dataclasses import dataclass

from config.config import get_config
from entities.MCPContext import MCPContext


class CredentialBrokerError(PermissionError):
    """Raised when role-scoped XSIAM credentials cannot be selected."""


@dataclass(frozen=True)
class CredentialSelection:
    auth_headers: dict[str, str]
    profile_name: str
    matched_group: str | None


def select_xsiam_credentials(context: MCPContext, fallback_headers: dict[str, str]) -> CredentialSelection:
    config = get_config()
    if not config.xsiam_credential_broker_enabled:
        return CredentialSelection(fallback_headers, "default", None)

    profiles = _parse_profiles(config.xsiam_credential_profiles)
    for group in context.groups:
        profile = profiles.get(group)
        if not profile:
            continue
        api_key = os.environ.get(profile["api_key_env"], "")
        api_key_id = os.environ.get(profile["api_key_id_env"], "")
        if not api_key or not api_key_id:
            raise CredentialBrokerError(f"XSIAM credential profile for group {group} is not fully configured")
        return CredentialSelection(
            {"Authorization": api_key, "X-XDR-AUTH-ID": api_key_id},
            profile.get("profile_name", group),
            group,
        )

    raise CredentialBrokerError(f"No XSIAM credential profile matches principal {context.principal_id}")


def _parse_profiles(raw_profiles: str) -> dict[str, dict[str, str]]:
    try:
        parsed = json.loads(raw_profiles or "{}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid XSIAM_CREDENTIAL_PROFILES JSON: {e}") from e

    if not isinstance(parsed, dict):
        raise ValueError("XSIAM_CREDENTIAL_PROFILES must be a JSON object mapping groups to profiles")

    profiles: dict[str, dict[str, str]] = {}
    for group, profile in parsed.items():
        if not isinstance(profile, dict):
            raise ValueError(f"Credential profile for group {group} must be an object")
        api_key_env = profile.get("api_key_env")
        api_key_id_env = profile.get("api_key_id_env")
        if not isinstance(api_key_env, str) or not isinstance(api_key_id_env, str):
            raise ValueError(f"Credential profile for group {group} requires api_key_env and api_key_id_env")
        profiles[str(group)] = {
            "api_key_env": api_key_env,
            "api_key_id_env": api_key_id_env,
            "profile_name": str(profile.get("profile_name") or group),
        }

    return profiles
