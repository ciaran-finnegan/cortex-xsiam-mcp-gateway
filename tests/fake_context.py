"""Async stand-in for fastmcp.Context used by tests that call tool functions directly.

FastMCP 3 state methods are coroutines. An earlier synchronous fake let un-awaited
``ctx.set_state`` calls pass; ``test_fake_context_matches_fastmcp_state_api`` keeps
this fake's signatures identical to the real Context so that cannot recur.
"""

import json
from types import SimpleNamespace
from typing import Any

from entities.MCPContext import MCPContext


class FakeContext:
    def __init__(
        self,
        lifespan_context: MCPContext,
        *,
        session_id: str = "unit-test-session",
        session_store: dict[str, Any] | None = None,
    ):
        self.request_context = SimpleNamespace(lifespan_context=lifespan_context)
        self.session_id = session_id
        self.session_store = {} if session_store is None else session_store
        self.request_state: dict[str, Any] = {}
        self.notifications: list[Any] = []

    def _key(self, key: str) -> str:
        return f"{self.session_id}:{key}"

    async def set_state(self, key: str, value: Any, *, serializable: bool = True) -> None:
        prefixed = self._key(key)
        if not serializable:
            self.request_state[prefixed] = value
            return
        self.request_state.pop(prefixed, None)
        # The real store round-trips through JSON; mirror that so non-JSON values fail here too.
        self.session_store[prefixed] = json.loads(json.dumps(value))

    async def get_state(self, key: str) -> Any:
        prefixed = self._key(key)
        if prefixed in self.request_state:
            return self.request_state[prefixed]
        return self.session_store.get(prefixed)

    async def delete_state(self, key: str) -> None:
        prefixed = self._key(key)
        self.request_state.pop(prefixed, None)
        self.session_store.pop(prefixed, None)

    async def send_notification(self, notification: Any) -> None:
        self.notifications.append(notification)

    def new_request(self) -> "FakeContext":
        """Return a context for the next request in the same session."""
        return FakeContext(
            self.request_context.lifespan_context,
            session_id=self.session_id,
            session_store=self.session_store,
        )


def fake_context(
    *,
    principal_id: str = "analyst@example.test",
    groups: tuple[str, ...] = ("Security",),
    auth_headers: dict[str, str] | None = None,
    session_id: str = "unit-test-session",
) -> FakeContext:
    return FakeContext(
        MCPContext(
            auth_headers=auth_headers if auth_headers is not None else {},
            principal_id=principal_id,
            groups=groups,
        ),
        session_id=session_id,
    )
