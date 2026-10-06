import asyncio

from app.services.model_loader import ModelLoader


class Flaky:
    name = "flaky"

    def __init__(self, failures):
        self.failures = failures
        self.attempts = 0
        self._ready = False

    @property
    def ready(self):
        return self._ready

    def load(self):
        self.attempts += 1
        if self.attempts <= self.failures:
            raise OSError("download failed")
        self._ready = True


async def test_retries_until_loaded():
    lifecycle = Flaky(failures=2)
    await ModelLoader(lifecycle, initial_delay=0.01, max_delay=0.02).run()
    assert lifecycle.ready and lifecycle.attempts == 3


async def test_skips_when_already_ready():
    lifecycle = Flaky(failures=0)
    lifecycle._ready = True
    await ModelLoader(lifecycle).run()
    assert lifecycle.attempts == 0


async def test_cancellation_stops_retrying():
    lifecycle = Flaky(failures=10**6)
    task = asyncio.create_task(ModelLoader(lifecycle, initial_delay=0.01, max_delay=0.01).run())
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert task.cancelled() and not lifecycle.ready
