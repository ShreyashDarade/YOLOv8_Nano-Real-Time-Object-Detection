import asyncio
import io

import pytest
from PIL import Image

from tests.conftest import image_bytes, make_service, make_settings

PNG = image_bytes()


def files(content=PNG, name="a.png", ctype="image/png", field="file"):
    return {field: (name, content, ctype)}


# --- probes & metadata ---------------------------------------------------------------------
async def test_healthz(client):
    r = await client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


async def test_readyz_ready(client):
    r = await client.get("/readyz")
    assert r.status_code == 200 and r.json()["model"] == "fake.pt"


async def test_readyz_not_ready_is_503_with_retry_after(detector, settings):
    import httpx

    from app.main import create_app

    detector._ready = False
    app = create_app(settings, make_service(detector, settings))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/readyz")
        assert r.status_code == 503 and r.json()["error"]["code"] == "model_not_ready"
        assert r.headers["retry-after"] == "5"
        d = await c.post("/v1/detect", files=files())
        assert d.status_code == 503


async def test_lifespan_loads_model_in_background(detector, settings):
    from app.main import create_app

    detector._ready = False
    app = create_app(settings, make_service(detector, settings))
    async with app.router.lifespan_context(app):
        for _ in range(50):
            if detector.ready:
                break
            await asyncio.sleep(0.02)
    assert detector.ready and detector.load_calls == 1


async def test_model_info(client):
    body = (await client.get("/v1/model")).json()
    assert body["classes"] == ["person", "car", "dog"] and body["class_count"] == 3
    assert body["limits"]["max_batch_files"] == 3
    assert body["limits"]["output_formats"] == ["jpeg", "png"]


# --- /v1/detect ----------------------------------------------------------------------------
async def test_detect_success_shape(client):
    r = await client.post("/v1/detect", files=files())
    assert r.status_code == 200
    body = r.json()
    assert body["model"] == "fake.pt" and body["count"] == 2
    assert body["image"] == {"width": 64, "height": 48}
    first = body["detections"][0]
    assert first["class_name"] == "person" and first["bbox"] == {
        "x1": 10, "y1": 10, "x2": 50, "y2": 60}
    assert r.headers["x-request-id"]


async def test_detect_passes_parameters(client, detector):
    r = await client.post(
        "/v1/detect?conf=0.6&iou=0.4&max_det=7&classes=person,dog&classes=car",
        files=files(),
    )
    assert r.status_code == 200
    p = detector.calls[0]
    assert (p.conf, p.iou, p.max_det, p.class_ids) == (0.6, 0.4, 7, (0, 1, 2))


async def test_detect_no_objects(client, detector):
    detector.detections = []
    body = (await client.post("/v1/detect", files=files())).json()
    assert body["count"] == 0 and body["detections"] == []


@pytest.mark.parametrize(
    "query", ["conf=1.5", "conf=-1", "conf=abc", "iou=2", "max_det=0", "max_det=1.5",
              "max_det=999999", "classes=unicorn"],
)
async def test_detect_invalid_parameters_422(client, query):
    r = await client.post(f"/v1/detect?{query}", files=files())
    assert r.status_code == 422
    assert r.json()["error"]["code"] in {"validation_error", "invalid_parameter"}


async def test_missing_file_field_422(client):
    r = await client.post("/v1/detect", files=files(field="wrong"))
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"


async def test_non_multipart_body_422(client):
    r = await client.post("/v1/detect", json={"file": "x"})
    assert r.status_code == 422


async def test_empty_file_400(client):
    r = await client.post("/v1/detect", files=files(b""))
    assert r.status_code == 400 and r.json()["error"]["code"] == "empty_upload"


async def test_non_image_400_even_with_image_content_type(client):
    r = await client.post("/v1/detect", files=files(b"hello world", "x.png", "image/png"))
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_image"


async def test_disguised_extension_judged_by_content_not_name(client):
    r = await client.post("/v1/detect", files=files(PNG, "photo.txt", "text/plain"))
    assert r.status_code == 200


async def test_unsupported_format_415(client):
    gif = image_bytes("GIF", size=(8, 8), mode="P")
    r = await client.post("/v1/detect", files=files(gif, "a.gif", "image/gif"))
    assert r.status_code == 415 and r.json()["error"]["code"] == "unsupported_image_format"


async def test_file_over_limit_413(client):
    big = image_bytes("BMP", size=(300, 300))  # ~270KB > 200KB limit
    r = await client.post("/v1/detect", files=files(big, "big.bmp", "image/bmp"))
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"


async def test_pixel_limit_413(client):
    r = await client.post("/v1/detect", files=files(image_bytes("PNG", size=(1100, 1000))))
    assert r.status_code == 413 and r.json()["error"]["code"] == "image_too_large"


async def test_truncated_image_400(client):
    r = await client.post("/v1/detect", files=files(image_bytes("PNG", size=(200, 200))[:200]))
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_image"


# --- request-level body limit ----------------------------------------------------------------
async def test_content_length_over_request_limit_rejected_early(client):
    r = await client.post("/v1/detect", content=b"x" * 700_000,
                          headers={"content-type": "multipart/form-data; boundary=b"})
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"


async def test_chunked_body_without_content_length_still_limited(client):
    async def body():
        yield b"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n\r\n"
        for _ in range(10):
            yield b"x" * 100_000
        yield b"\r\n--b--\r\n"

    r = await client.post("/v1/detect", content=body(),
                          headers={"content-type": "multipart/form-data; boundary=b"})
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"
    assert r.headers.get_list("x-request-id").__len__() == 1


# --- batch -----------------------------------------------------------------------------------
async def test_batch_mixed_results(client):
    multi = [("files", ("ok.png", PNG, "image/png")),
             ("files", ("empty.png", b"", "image/png")),
             ("files", ("bad.png", b"junk", "image/png"))]
    r = await client.post("/v1/detect/batch", files=multi)
    assert r.status_code == 200
    body = r.json()
    assert (body["total"], body["succeeded"], body["failed"]) == (3, 1, 2)
    statuses = {i["filename"]: i for i in body["items"]}
    assert statuses["ok.png"]["status"] == "ok" and statuses["ok.png"]["result"]["count"] == 2
    assert statuses["empty.png"]["error"]["code"] == "empty_upload"
    assert statuses["bad.png"]["error"]["code"] == "invalid_image"
    assert [i["filename"] for i in body["items"]] == ["ok.png", "empty.png", "bad.png"]


async def test_batch_too_many_files(client):
    multi = [("files", (f"{i}.png", PNG, "image/png")) for i in range(4)]
    r = await client.post("/v1/detect/batch", files=multi)
    assert r.status_code == 413 and r.json()["error"]["code"] == "too_many_files"


async def test_batch_without_files_422(client):
    assert (await client.post("/v1/detect/batch")).status_code == 422


async def test_batch_filename_is_sanitised(client):
    multi = [("files", ("../../etc/passwd.png", PNG, "image/png")),
             ("files", ("C:\\evil\\win.png", PNG, "image/png"))]
    body = (await client.post("/v1/detect/batch", files=multi)).json()
    assert [i["filename"] for i in body["items"]] == ["passwd.png", "win.png"]


async def test_batch_invalid_option_422(client):
    r = await client.post("/v1/detect/batch?conf=9", files=[("files", ("a.png", PNG, "image/png"))])
    assert r.status_code == 422


# --- annotated -----------------------------------------------------------------------------------
@pytest.mark.parametrize("fmt,ctype", [("jpeg", "image/jpeg"), ("png", "image/png")])
async def test_annotated(client, fmt, ctype):
    r = await client.post(f"/v1/detect/annotated?format={fmt}", files=files())
    assert r.status_code == 200 and r.headers["content-type"] == ctype
    assert r.headers["x-detection-count"] == "2"
    assert Image.open(io.BytesIO(r.content)).size == (64, 48)


async def test_annotated_bad_format_422(client):
    r = await client.post("/v1/detect/annotated?format=tiff", files=files())
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_parameter"


# --- auth ------------------------------------------------------------------------------------------
@pytest.fixture
def secured(detector):
    import httpx

    from app.main import create_app

    s = make_settings(api_keys=["k1", "k2"])
    app = create_app(s, make_service(detector, s))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def test_auth_rejects_missing_and_wrong_keys(secured):
    async with secured as c:
        for headers in ({}, {"X-API-Key": "nope"}, {"Authorization": "Bearer nope"},
                        {"Authorization": "Basic k1"}, {"Authorization": "Bearer "}):
            r = await c.post("/v1/detect", files=files(), headers=headers)
            assert r.status_code == 401, headers
            assert r.json()["error"]["code"] == "unauthorized"
            assert r.headers["www-authenticate"] == "Bearer"


async def test_auth_accepts_either_key_and_both_styles(secured):
    async with secured as c:
        assert (await c.post("/v1/detect", files=files(), headers={"X-API-Key": "k2"})).status_code == 200
        assert (await c.post("/v1/detect", files=files(),
                             headers={"Authorization": "Bearer k1"})).status_code == 200
        assert (await c.get("/v1/model")).status_code == 401


async def test_probes_do_not_require_auth(secured):
    async with secured as c:
        assert (await c.get("/healthz")).status_code == 200
        assert (await c.get("/readyz")).status_code == 200


# --- cross-cutting -----------------------------------------------------------------------------------
async def test_request_id_is_echoed_when_valid_and_replaced_when_not(client):
    ok = await client.get("/healthz", headers={"X-Request-ID": "abc-123"})
    assert ok.headers["x-request-id"] == "abc-123"
    bad = await client.get("/healthz", headers={"X-Request-ID": "bad id\twith spaces"})
    assert bad.headers["x-request-id"] != "bad id\twith spaces" and len(bad.headers["x-request-id"]) == 32


async def test_error_body_carries_request_id(client):
    r = await client.post("/v1/detect", files=files(b""), headers={"X-Request-ID": "rid-1"})
    assert r.json()["error"]["request_id"] == "rid-1"


async def test_unknown_route_and_wrong_method_use_envelope(client):
    nf = await client.get("/nope")
    assert nf.status_code == 404 and nf.json()["error"]["code"] == "not_found"
    mna = await client.get("/v1/detect")
    assert mna.status_code == 405 and mna.json()["error"]["code"] == "method_not_allowed"


async def test_inference_failure_returns_500_without_internal_details(client, detector):
    detector.error = RuntimeError("CUDA OOM at /srv/secret")
    r = await client.post("/v1/detect", files=files())
    assert r.status_code == 500 and "secret" not in r.text
    assert r.json()["error"]["code"] == "inference_failed"


async def test_timeout_is_504():
    import httpx

    from app.main import create_app
    from tests.conftest import FakeDetector

    det = FakeDetector()
    det.delay = 0.5
    s = make_settings(inference_timeout_s=0.05)
    app = create_app(s, make_service(det, s))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/detect", files=files())
    assert r.status_code == 504 and r.json()["error"]["code"] == "inference_timeout"


async def test_overload_returns_503_with_retry_after_then_recovers():
    import httpx

    from app.main import create_app
    from tests.conftest import FakeDetector

    det = FakeDetector()
    det.delay = 0.3
    s = make_settings(max_concurrent_inferences=1, max_pending_requests=0)
    app = create_app(s, make_service(det, s))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        first = asyncio.create_task(c.post("/v1/detect", files=files()))
        await asyncio.sleep(0.1)
        second = await c.post("/v1/detect", files=files())
        assert second.status_code == 503 and second.headers["retry-after"] == "1"
        assert second.json()["error"]["code"] == "service_busy"
        assert (await first).status_code == 200
        assert (await c.post("/v1/detect", files=files())).status_code == 200


async def test_concurrent_requests_within_queue_all_succeed():
    import httpx

    from app.main import create_app
    from tests.conftest import FakeDetector

    det = FakeDetector()
    det.delay = 0.05
    s = make_settings(max_concurrent_inferences=1, max_pending_requests=5)
    app = create_app(s, make_service(det, s))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        rs = await asyncio.gather(*[c.post("/v1/detect", files=files()) for _ in range(5)])
    assert [r.status_code for r in rs] == [200] * 5


async def test_docs_can_be_disabled(detector):
    import httpx

    from app.main import create_app

    s = make_settings(docs_enabled=False)
    app = create_app(s, make_service(detector, s))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/docs")).status_code == 404
        assert (await c.get("/openapi.json")).status_code == 404


async def test_cors_only_for_configured_origins(detector):
    import httpx

    from app.main import create_app

    s = make_settings(cors_origins=["https://ok.test"])
    app = create_app(s, make_service(detector, s))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        good = await c.get("/healthz", headers={"Origin": "https://ok.test"})
        bad = await c.get("/healthz", headers={"Origin": "https://evil.test"})
    assert good.headers["access-control-allow-origin"] == "https://ok.test"
    assert "access-control-allow-origin" not in bad.headers
