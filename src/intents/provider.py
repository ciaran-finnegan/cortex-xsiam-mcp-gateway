"""The inference provider of the intent pilot: an interface, and one adapter for the common JSON format.

There is no default vendor and no built-in endpoint. The adapter speaks the chat-completions JSON
format that most providers and internal AI gateways accept, to whatever URL the operator sets. To
reach something else, implement ``LabelProvider`` and return it from ``build_provider``.

Nothing outside this package imports this module, which keeps the guarantee that the gateway and
the learner call no model.
"""

import json
from typing import Any, Protocol
from urllib.parse import urlsplit

import requests

from intents.settings import IntentSettings, IntentSettingsError

MAX_REPLY_BYTES = 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 10.0
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class ProviderError(RuntimeError):
    """A failed call, with a short code. It never carries the request, the reply or the credential."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class LabelProvider(Protocol):
    host: str
    model: str

    def complete(self, system: str, user: str) -> str:
        """The model's reply text. Raises ProviderError when there is none."""
        ...


class ChatCompletionsProvider:
    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        api_key: str,
        auth_header: str,
        extra_body: dict[str, Any],
        timeout_seconds: float,
    ):
        self.endpoint = endpoint
        self.host = urlsplit(endpoint).hostname or ""
        self.model = model
        self._headers = {"Content-Type": "application/json"}
        if api_key:
            self._headers[auth_header] = f"Bearer {api_key}" if auth_header.lower() == "authorization" else api_key
        self._extra_body = extra_body
        self._timeout = (CONNECT_TIMEOUT_SECONDS, timeout_seconds)

    def complete(self, system: str, user: str) -> str:
        body = {
            **self._extra_body,
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        try:
            # A redirect would carry query text, and maybe the credential, to a host nobody configured.
            response = requests.post(
                self.endpoint, json=body, headers=self._headers, timeout=self._timeout, allow_redirects=False
            )
        except requests.RequestException as e:
            raise ProviderError(type(e).__name__) from None
        if response.status_code != 200:
            raise ProviderError(f"http_{response.status_code}")
        if len(response.content) > MAX_REPLY_BYTES:
            raise ProviderError("reply_too_large")
        try:
            content = response.json()["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise ProviderError("unexpected_reply_shape") from None
        if not isinstance(content, str):
            raise ProviderError("unexpected_reply_shape")
        return content


def _endpoint_allowed(endpoint: str) -> bool:
    parts = urlsplit(endpoint)
    if parts.username or parts.password or not parts.hostname:
        return False
    return parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS)


def _extra_body(settings: IntentSettings) -> dict[str, Any] | None:
    try:
        extra = json.loads(settings.provider_extra_body)
    except json.JSONDecodeError:
        return None
    return extra if isinstance(extra, dict) and not {"model", "messages"} & set(extra) else None


def build_provider(settings: IntentSettings) -> LabelProvider:
    """The provider the operator configured. Raises IntentSettingsError naming what is missing or invalid."""
    problems = []
    if not _endpoint_allowed(settings.provider_endpoint):
        problems.append("INTENT_PROVIDER_ENDPOINT")
    if not settings.provider_model:
        problems.append("INTENT_PROVIDER_MODEL")
    api_key = settings.provider_api_key.get_secret_value()
    is_loopback = urlsplit(settings.provider_endpoint).hostname in _LOOPBACK_HOSTS
    if not api_key and not is_loopback:
        problems.append("INTENT_PROVIDER_API_KEY")
    extra_body = _extra_body(settings)
    if extra_body is None:
        problems.append("INTENT_PROVIDER_EXTRA_BODY")
    if problems:
        raise IntentSettingsError(problems)
    return ChatCompletionsProvider(
        endpoint=settings.provider_endpoint,
        model=settings.provider_model,
        api_key=api_key,
        auth_header=settings.provider_auth_header,
        extra_body=extra_body or {},
        timeout_seconds=settings.provider_timeout_seconds,
    )
