from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

from app.core.errors import ServiceBusyError


class AdmissionController:
    """Bounds concurrent work and the queue behind it (backpressure).

    At most ``max_concurrent`` callers run; up to ``max_pending`` more may wait. Anything
    beyond that is rejected immediately with a retryable 503 instead of piling up memory
    and latency.
    """

    def __init__(self, max_concurrent: int, max_pending: int) -> None:
        self._sem = asyncio.Semaphore(max_concurrent)
        self._max_pending = max_pending
        self._waiting = 0

    @property
    def waiting(self) -> int:
        return self._waiting

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        # No awaits between the check and the increment, so this is race-free on one loop.
        if self._sem.locked() and self._waiting >= self._max_pending:
            raise ServiceBusyError()
        self._waiting += 1
        try:
            await self._sem.acquire()
        finally:
            self._waiting -= 1
        try:
            yield
        finally:
            self._sem.release()
