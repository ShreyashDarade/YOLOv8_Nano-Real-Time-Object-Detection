"""Pure-ASGI middleware (no BaseHTTPMiddleware, so streaming/cancellation stay correct)."""
from __future__ import annotations

import json
import logging
import re
import time
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import PayloadTooLargeError

logger = logging.getLogger("app.access")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class RequestContextMiddleware:
    """Assigns/propagates ``X-Request-ID`` and writes one access-log line per request."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = dict(scope["headers"]).get(b"x-request-id", b"").decode("latin-1")
        # Never trust a client value blindly: it ends up in logs and response headers.
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.perf_counter()
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = message.setdefault("headers", [])
                if not any(name.lower() == b"x-request-id" for name, _ in headers):
                    headers.append((b"x-request-id", request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            logger.info(
                "%s %s -> %s in %.1fms [%s]",
                scope["method"], scope["path"], status,
                (time.perf_counter() - started) * 1000, request_id,
            )


class BodySizeLimitMiddleware:
    """Rejects oversized request bodies before they are buffered.

    Checks ``Content-Length`` up front and also counts streamed bytes, so chunked uploads
    with no declared length (or a lying one) are stopped too. Frameworks may wrap errors
    raised while reading the body (FastAPI turns them into a generic 400), so once the limit
    is crossed this middleware owns the response and replaces whatever the app sends with a
    413.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                too_big = False  # malformed length: the server/parser will reject it
            if too_big:
                await self._respond_413(scope, send)
                return

        received = 0
        exceeded = False
        responded = False

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise PayloadTooLargeError(f"Request body exceeds {self.max_bytes} bytes")
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal responded
            if not exceeded:
                await send(message)
            elif not responded:
                responded = True
                await self._respond_413(scope, send)
            # else: swallow the rest of the app's (now irrelevant) response

        await self.app(scope, limited_receive, guarded_send)

    async def _respond_413(self, scope: Scope, send: Send) -> None:
        request_id = scope.get("state", {}).get("request_id")
        body = json.dumps({
            "error": {
                "code": PayloadTooLargeError.code,
                "message": f"Request body exceeds {self.max_bytes} bytes",
                "request_id": request_id,
            }
        }).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"connection", b"close"),
        ]
        await send({"type": "http.response.start", "status": 413, "headers": headers})
        await send({"type": "http.response.body", "body": body})
