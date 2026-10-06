"""Pure domain types. No framework or ML-library imports."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence, Tuple

import numpy as np


@dataclass(frozen=True)
class BoundingBox:
    """Pixel coordinates in the original image, top-left origin."""

    x1: float
    y1: float
    x2: float
    y2: float


@dataclass(frozen=True)
class Detection:
    class_id: int
    class_name: str
    confidence: float
    box: BoundingBox


@dataclass(frozen=True)
class DetectionParams:
    conf: float
    iou: float
    max_det: int
    class_ids: Optional[Tuple[int, ...]] = None


@dataclass(frozen=True)
class DecodedImage:
    """An RGB, uint8, HxWx3 image."""

    pixels: np.ndarray = field(repr=False, compare=False)
    width: int
    height: int
    format: str


@dataclass(frozen=True)
class DetectionResult:
    width: int
    height: int
    detections: Sequence[Detection]
    inference_ms: float
