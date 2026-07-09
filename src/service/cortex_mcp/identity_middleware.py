import json

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from starlette.authentication import AuthCredentials
from starlette.types import ASGIApp, Receive, Scope, Send

from usecase.identity import IdentityAuthenticationError, authenticate_http_headers


class IdentityMiddleware:
    """Validate incoming HTTP identity before MCP requests reach FastMCP."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in {"/ping", "/ping/"}:
            await self.app(scope, receive, send)
            return

        headers = {key.decode(): value.decode() for key, value in scope.get("headers", [])}
        try:
            access_token = await authenticate_http_headers(headers)
        except IdentityAuthenticationError as e:
            await self._send_auth_error(send, str(e))
            return

        if access_token:
            scope["auth"] = AuthCredentials(access_token.scopes)
            scope["user"] = AuthenticatedUser(access_token)

        await self.app(scope, receive, send)

    async def _send_auth_error(self, send: Send, description: str) -> None:
        body = json.dumps({"error": "invalid_token", "error_description": description}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"www-authenticate", b'Bearer error="invalid_token"'),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
