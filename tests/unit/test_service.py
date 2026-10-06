import asyncio

import pytest

from app.core.errors import (
    InferenceFailedError,
    InferenceTimeoutError,
    InvalidImageError,
    InvalidParameterError,
    ModelNotReadyError,
    ServiceBusyError,
)
from app.services.detection_service import DetectionOptions
from tests.conftest import FakeDetector, image_bytes, make_service, make_settings

PNG = image_bytes()
OPTS = DetectionOptions()


async def test_defaults_applied(service, detector):
    result = await service.detect(PNG, OPTS)
    p = detector.calls[0]
    assert (p.conf, p.iou, p.max_det, p.class_ids) == (0.25, 0.7, 100, None)
    assert (result.width, result.height) == (64, 48)
    assert len(result.detections) == 2 and result.inference_ms >= 0


async def test_class_names_resolved_case_insensitively_and_deduped(service, detector):
    await service.detect(PNG, DetectionOptions(classes=["DOG", " person ", "dog", ""]))
    assert detector.calls[0].class_ids == (0, 2)


async def test_blank_class_filter_means_all(service, detector):
    await service.detect(PNG, DetectionOptions(classes=["", " "]))
    assert detector.calls[0].class_ids is None


@pytest.mark.parametrize(
    "opts",
    [
        DetectionOptions(conf=-0.1), DetectionOptions(conf=1.1), DetectionOptions(iou=2),
        DetectionOptions(max_det=0), DetectionOptions(max_det=10**6),
        DetectionOptions(classes=["unicorn"]),
    ],
)
async def test_invalid_options_rejected_before_inference(service, detector, opts):
    with pytest.raises(InvalidParameterError):
        await service.detect(PNG, opts)
    assert detector.calls == []


async def test_boundary_option_values_accepted(service):
    await service.detect(PNG, DetectionOptions(conf=0, iou=1, max_det=1000))


async def test_not_ready(settings):
    det = FakeDetector(ready=False)
    with pytest.raises(ModelNotReadyError):
        await make_service(det, settings).detect(PNG, OPTS)


async def test_decode_errors_propagate_unchanged(service):
    with pytest.raises(InvalidImageError):
        await service.detect(b"junk", OPTS)


async def test_unexpected_detector_error_is_wrapped_without_leaking(service, detector):
    detector.error = RuntimeError("secret internal path /srv/x")
    with pytest.raises(InferenceFailedError) as exc:
        await service.detect(PNG, OPTS)
    assert "secret" not in exc.value.message


async def test_timeout():
    det = FakeDetector()
    det.delay = 0.5
    svc = make_service(det, make_settings(inference_timeout_s=0.05))
    with pytest.raises(InferenceTimeoutError):
        await svc.detect(PNG, OPTS)


async def test_busy_when_queue_full():
    det = FakeDetector()
    det.delay = 0.2
    svc = make_service(det, make_settings(max_concurrent_inferences=1, max_pending_requests=0))
    first = asyncio.create_task(svc.detect(PNG, OPTS))
    await asyncio.sleep(0.05)
    with pytest.raises(ServiceBusyError):
        await svc.detect(PNG, OPTS)
    await first
    await svc.detect(PNG, OPTS)  # capacity recovered


async def test_batch_isolates_per_file_failures(service):
    out = await service.detect_many([("a.png", PNG), ("bad.png", b"junk"), ("c.png", PNG)], OPTS)
    assert [o.error is None for o in out] == [True, False, True]
    assert out[1].error.code == "invalid_image"


async def test_batch_bad_options_fail_fast(service, detector):
    with pytest.raises(InvalidParameterError):
        await service.detect_many([("a.png", PNG)], DetectionOptions(conf=5))
    assert detector.calls == []


async def test_batch_aborts_when_busy():
    det = FakeDetector()
    det.delay = 0.2
    svc = make_service(det, make_settings(max_concurrent_inferences=1, max_pending_requests=0))
    blocker = asyncio.create_task(svc.detect(PNG, OPTS))
    await asyncio.sleep(0.05)
    with pytest.raises(ServiceBusyError):
        await svc.detect_many([("a.png", PNG)], OPTS)
    await blocker


async def test_annotate_unsupported_format_rejected_before_work(service, detector):
    with pytest.raises(InvalidParameterError):
        await service.annotate(PNG, OPTS, "tiff")
    assert detector.calls == []


async def test_annotate_returns_image_bytes(service):
    data, result = await service.annotate(PNG, OPTS, "png")
    assert data[:4] == b"\x89PNG" and len(result.detections) == 2
