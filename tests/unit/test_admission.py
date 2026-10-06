import asyncio

import pytest

from app.core.errors import ServiceBusyError
from app.services.admission import AdmissionController


async def test_rejects_when_capacity_and_queue_full():
    ctl = AdmissionController(max_concurrent=1, max_pending=1)
    release = asyncio.Event()

    async def hold():
        async with ctl.slot():
            await release.wait()

    running = asyncio.create_task(hold())
    await asyncio.sleep(0)
    queued = asyncio.create_task(hold())
    await asyncio.sleep(0)
    assert ctl.waiting == 1
    with pytest.raises(ServiceBusyError):
        async with ctl.slot():
            pass
    release.set()
    await asyncio.gather(running, queued)
    assert ctl.waiting == 0


async def test_slot_released_after_exception():
    ctl = AdmissionController(max_concurrent=1, max_pending=0)
    with pytest.raises(RuntimeError):
        async with ctl.slot():
            raise RuntimeError
    async with ctl.slot():
        pass


async def test_cancelled_waiter_does_not_leak_queue_position():
    ctl = AdmissionController(max_concurrent=1, max_pending=1)
    release = asyncio.Event()

    async def hold():
        async with ctl.slot():
            await release.wait()

    running = asyncio.create_task(hold())
    await asyncio.sleep(0)
    waiter = asyncio.create_task(hold())
    await asyncio.sleep(0)
    waiter.cancel()
    await asyncio.gather(waiter, return_exceptions=True)
    assert ctl.waiting == 0
    release.set()
    await running
