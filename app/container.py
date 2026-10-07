"""Composition root: the only place that knows which concrete classes are used."""
from __future__ import annotations

from app.core.config import Settings
from app.infrastructure.image_annotator import PillowImageAnnotator
from app.infrastructure.image_decoder import PillowImageDecoder
from app.infrastructure.yolo_detector import YoloDetector
from app.services.admission import AdmissionController
from app.services.detection_service import DetectionService, ServiceLimits


def build_service(settings: Settings) -> DetectionService:
    detector = YoloDetector(settings.weights, settings.device, settings.imgsz)
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

