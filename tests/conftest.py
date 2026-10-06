from __future__ import annotations

import io
import threading
import time
from typing import List, Optional, Sequence

import httpx
import pytest
import pytest_asyncio
from PIL import Image

from app.core.config import Settings
from app.domain.interfaces import Detector, ModelLifecycle
from app.domain.models import BoundingBox, DecodedImage, Detection, DetectionParams
from app.infrastructure.image_annotator import PillowImageAnnotator
from app.infrastructure.image_decoder import PillowImageDecoder
from app.main import create_app
from app.services.admission import AdmissionController
from app.services.detection_service import DetectionService, ServiceLimits

CLASS_NAMES = ["person", "car", "dog"]


class FakeDetector(Detector, ModelLifecycle):
    """Deterministic stand-in: any Detector/ModelLifecycle must be substitutable (LSP)."""

    def __init__(self, detections: Optional[List[Detection]] = None, ready: bool = True):
        self.detections = detections if detections is not None else [
            Detection(0, "person", 0.9, BoundingBox(10, 10, 50, 60)),
            Detection(1, "car", 0.5, BoundingBox(-5, 0, 9999, 40)),
        ]
        self._ready = ready
        self.delay = 0.0
        self.error: Optional[Exception] = None
        self.calls: List[DetectionParams] = []
        self.load_calls = 0
        self._lock = threading.Lock()

    @property
    def class_names(self) -> Sequence[str]:
        return CLASS_NAMES

    @property
    def name(self) -> str:
        return "fake.pt"

    @property
    def ready(self) -> bool:
        return self._ready

    def load(self) -> None:
        self.load_calls += 1
        self._ready = True

    def detect(self, image: DecodedImage, params: DetectionParams) -> List[Detection]:
        with self._lock:
            self.calls.append(params)
        if self.delay:
            time.sleep(self.delay)
        if self.error:
            raise self.error
        return list(self.detections)


def make_settings(**overrides) -> Settings:
    base = dict(
        max_upload_bytes=200_000, max_request_bytes=600_000, max_image_pixels=1_000_000,
        max_batch_files=3, max_pending_requests=2, inference_timeout_s=5, _env_file=None,
    )
    base.update(overrides)
    return Settings(**base)


def make_service(detector: FakeDetector, settings: Settings) -> DetectionService:
    return DetectionService(
        detector=detector,
        lifecycle=detector,
        decoder=PillowImageDecoder(settings.allowed_formats, settings.max_image_pixels),
        annotator=PillowImageAnnotator(),
        admission=AdmissionController(
            settings.max_concurrent_inferences, settings.max_pending_requests
        ),
        limits=ServiceLimits(
            default_conf=settings.default_conf,
            default_iou=settings.default_iou,
            default_max_det=settings.default_max_det,
            max_det_limit=settings.max_det_limit,
            timeout_s=settings.inference_timeout_s,
        ),
    )


def image_bytes(fmt: str = "PNG", size=(64, 48), mode: str = "RGB", **save_kwargs) -> bytes:
    buf = io.BytesIO()
    Image.new(mode, size, "white" if mode != "P" else 0).save(buf, format=fmt, **save_kwargs)
    return buf.getvalue()


@pytest.fixture
def detector() -> FakeDetector:
    return FakeDetector()


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def service(detector, settings) -> DetectionService:
    return make_service(detector, settings)


@pytest.fixture
def app(service, settings):
    return create_app(settings, service)


@pytest_asyncio.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
