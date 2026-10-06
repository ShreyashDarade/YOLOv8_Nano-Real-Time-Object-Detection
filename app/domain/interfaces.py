"""Abstractions the service layer depends on (Dependency Inversion).

The interfaces are deliberately small and separate (Interface Segregation): a component
that only needs to draw boxes never sees model-loading concerns, and vice versa.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Sequence

from .models import DecodedImage, Detection, DetectionParams


class Detector(ABC):
    """Runs object detection on an RGB image."""

    @property
    @abstractmethod
    def class_names(self) -> Sequence[str]: ...

    @abstractmethod
    def detect(self, image: DecodedImage, params: DetectionParams) -> List[Detection]:
        """Return detections in original-image pixel coordinates. Must be thread-safe."""


class ModelLifecycle(ABC):
    """Loads/unloads a model and reports whether it can serve requests."""

    @abstractmethod
    def load(self) -> None: ...

    @property
    @abstractmethod
    def ready(self) -> bool: ...

    @property
    @abstractmethod
    def name(self) -> str: ...


class ImageDecoder(ABC):
    """Turns untrusted bytes into a validated RGB image or raises an ``AppError``."""

    @abstractmethod
    def decode(self, data: bytes) -> DecodedImage: ...


class ImageAnnotator(ABC):
    """Renders detections onto an image and encodes it."""

    @abstractmethod
    def render(self, image: DecodedImage, detections: Sequence[Detection], fmt: str) -> bytes: ...

    @property
    @abstractmethod
    def supported_formats(self) -> Sequence[str]: ...
