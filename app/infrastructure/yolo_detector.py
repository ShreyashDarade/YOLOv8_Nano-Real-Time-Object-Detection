from __future__ import annotations

import logging
import os
import threading
from typing import List, Optional, Sequence

import numpy as np

from app.core.errors import ModelNotReadyError
from app.domain.interfaces import Detector, ModelLifecycle
from app.domain.models import BoundingBox, DecodedImage, Detection, DetectionParams

logger = logging.getLogger(__name__)


class YoloDetector(Detector, ModelLifecycle):
    """Ultralytics YOLOv8 adapter.

    ``ultralytics`` is imported lazily so the rest of the app (and its tests) work without
    the heavy ML stack. Predictions are serialized with a lock because a single model
    instance is not guaranteed to be thread-safe.
    """

    def __init__(self, weights: str, device: str, imgsz: int) -> None:
        self._weights = weights
        self._device = device
        self._imgsz = imgsz
        self._model = None
        self._names: List[str] = []
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return os.path.basename(self._weights)

    @property
    def ready(self) -> bool:
        return self._model is not None

    @property
    def class_names(self) -> Sequence[str]:
        return list(self._names)

    def load(self) -> None:
        from ultralytics import YOLO

        model = YOLO(self._weights)
        names = model.names
        self._names = [names[i] for i in sorted(names)]
        # Warm up so the first real request doesn't pay lazy-initialisation cost.
        model.predict(
            np.zeros((self._imgsz, self._imgsz, 3), dtype=np.uint8),
            imgsz=self._imgsz, device=self._device, verbose=False,
        )
        self._model = model
        logger.info(
            "Loaded model %s on %s with %d classes", self.name, self._device, len(self._names)
        )

    def detect(self, image: DecodedImage, params: DetectionParams) -> List[Detection]:
        model = self._model
        if model is None:
            raise ModelNotReadyError()
        bgr = np.ascontiguousarray(image.pixels[:, :, ::-1])  # Ultralytics expects BGR arrays
        with self._lock:
            result = model.predict(
                bgr,
                imgsz=self._imgsz,
                conf=params.conf,
                iou=params.iou,
                max_det=params.max_det,
                classes=list(params.class_ids) if params.class_ids is not None else None,
                device=self._device,
                verbose=False,
            )[0]
        return self._to_detections(result, image.width, image.height)

    def _to_detections(self, result, width: int, height: int) -> List[Detection]:
        boxes: Optional[object] = result.boxes
        if boxes is None or len(boxes) == 0:
            return []
        xyxy = boxes.xyxy.cpu().numpy()
        conf = boxes.conf.cpu().numpy()
        cls = boxes.cls.cpu().numpy().astype(int)
        detections = []
        for (x1, y1, x2, y2), c, k in zip(xyxy, conf, cls, strict=True):
            detections.append(
                Detection(
                    class_id=int(k),
                    class_name=self._names[int(k)] if 0 <= int(k) < len(self._names) else str(k),
                    confidence=float(c),
                    box=BoundingBox(
                        x1=float(np.clip(x1, 0, width)), y1=float(np.clip(y1, 0, height)),
                        x2=float(np.clip(x2, 0, width)), y2=float(np.clip(y2, 0, height)),
                    ),
                )
            )
        return detections
