from __future__ import annotations

import asyncio
import logging

import anyio

from app.domain.interfaces import ModelLifecycle

logger = logging.getLogger(__name__)


class ModelLoader:
    """Loads the model in the background, retrying with capped exponential backoff.

    The API starts immediately and reports not-ready (503) until loading succeeds, so a
    transient failure (e.g. weights download) heals itself instead of leaving a dead pod.
    """

    def __init__(
        self, lifecycle: ModelLifecycle, initial_delay: float = 2.0, max_delay: float = 60.0
    ) -> None:
        self._lifecycle = lifecycle
        self._initial = initial_delay
        self._max = max_delay

    async def run(self) -> None:
        delay = self._initial
        while not self._lifecycle.ready:
            try:
                await anyio.to_thread.run_sync(self._lifecycle.load)
                return
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Model load failed; retrying in %.1fs", delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._max)
