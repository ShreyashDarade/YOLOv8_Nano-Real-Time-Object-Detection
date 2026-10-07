"""End-to-end against the real YOLOv8n weights (downloaded on first run).

Run with:  pytest -m integration -o addopts=""
"""
import httpx
import pytest

from app.main import create_app
from tests.conftest import image_bytes, make_settings

pytest.importorskip("ultralytics")
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def real_app():
    from app.container import build_service

    settings = make_settings(max_upload_bytes=5_000_000, max_request_bytes=10_000_000)
    service = build_service(settings)
    service.lifecycle.load()
    return create_app(settings, service)


@pytest.mark.parametrize("size", [(1, 1), (7, 3), (640, 480), (1000, 20)])
async def test_odd_image_sizes_do_not_crash(real_app, size):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=real_app), base_url="http://t") as c:
        r = await c.post("/v1/detect", files={"file": ("x.png", image_bytes("PNG", size=size), "image/png")})
    assert r.status_code == 200, r.text
    assert r.json()["image"] == {"width": size[0], "height": size[1]}


async def test_model_metadata_and_class_filter(real_app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=real_app), base_url="http://t") as c:
        info = (await c.get("/v1/model")).json()
        assert info["class_count"] == 80 and "person" in info["classes"]
        r = await c.post("/v1/detect?classes=person",
                         files={"file": ("x.png", image_bytes("PNG", size=(320, 320)), "image/png")})
        assert r.status_code == 200
