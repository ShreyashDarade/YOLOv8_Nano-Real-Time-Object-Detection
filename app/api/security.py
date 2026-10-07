from __future__ import annotations

import secrets
from typing import Optional

from fastapi import Request

from app.core.errors import UnauthorizedError


def _presented_key(request: Request) -> Optional[str]:
    key = request.headers.get("x-api-key")
    if key:
        return key
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


async def require_api_key(request: Request) -> None:
    """Authenticates when keys are configured; open otherwise (e.g. behind a gateway)."""
    configured = request.app.state.settings.api_keys
    if not configured:
        return
    presented = _presented_key(request)
    # Compare against every key (no early exit) in constant time to avoid timing leaks.
    matched = False
    for key in configured:
        matched |= presented is not None and secrets.compare_digest(
            presented.encode(), key.encode()
        )
    if not matched:
        raise UnauthorizedError("Missing or invalid API key")
