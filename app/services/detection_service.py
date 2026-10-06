from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple, TypeVar

import anyio

from app.core.errors import (
    AppError,
    InferenceFailedError,
    InferenceTimeoutError,
    InvalidParameterError,
    ModelNotReadyError,
    ServiceBusyError,
)
from app.domain.interfaces import Detector, ImageAnnotator, ImageDecoder, ModelLifecycle
from app.domain.models import DecodedImage, DetectionParams, DetectionResult
from app.services.admission import AdmissionController

logger = logging.getLogger(__name__)
T = TypeVar("T")


@dataclass(frozen=True)
class DetectionOptions:
    """Caller-supplied options; ``None`` means "use the server default"."""

    conf: Optional[float] = None
    iou: Optional[float] = None
    max_det: Optional[int] = None
    classes: Optional[Sequence[str]] = None


@dataclass(frozen=True)
class ServiceLimits:
    default_conf: float
    default_iou: float
    default_max_det: int
    max_det_limit: int
    timeout_s: float


@dataclass(frozen=True)
class BatchOutcome:
    filename: str
    result: Optional[DetectionResult] = None
    error: Optional[AppError] = None


class DetectionService:
    """Orchestrates decode -> detect -> (annotate). Depends only on abstractions."""

    def __init__(
        self,
        detector: Detector,
        lifecycle: ModelLifecycle,
        decoder: ImageDecoder,
        annotator: ImageAnnotator,
        admission: AdmissionController,
        limits: ServiceLimits,
    ) -> None:
        self._detector = detector
        self._lifecycle = lifecycle
        self._decoder = decoder
        self._annotator = annotator
        self._admission = admission
        self._limits = limits

    @property
    def lifecycle(self) -> ModelLifecycle:
        return self._lifecycle

    # -- introspection -------------------------------------------------------------------
    @property
    def ready(self) -> bool:
        return self._lifecycle.ready

    @property
    def model_name(self) -> str:
        return self._lifecycle.name

    @property
    def class_names(self) -> Sequence[str]:
        return self._detector.class_names

    @property
    def output_formats(self) -> Sequence[str]:
        return self._annotator.supported_formats

    # -- public operations ---------------------------------------------------------------
    async def detect(self, data: bytes, options: DetectionOptions) -> DetectionResult:
        _, result = await self._analyze(data, options)
        return result

    async def annotate(
        self, data: bytes, options: DetectionOptions, fmt: str
    ) -> Tuple[bytes, DetectionResult]:
        if fmt.lower() not in self._annotator.supported_formats:
            raise InvalidParameterError(
                f"Unsupported output format {fmt!r}; use one of "
                f"{', '.join(self._annotator.supported_formats)}"
            )
        image, result = await self._analyze(data, options)
        rendered = await self._run(lambda: self._annotator.render(image, result.detections, fmt))
        return rendered, result

    async def detect_many(
        self, items: Sequence[Tuple[str, bytes]], options: DetectionOptions
    ) -> List[BatchOutcome]:
        """Per-file outcomes: one bad image must not fail the whole batch.

        Capacity/readiness problems affect every item, so they abort the request instead.
        """
        if not self.ready:
            raise ModelNotReadyError()
        self._params(options)  # fail fast on bad options, before touching any file
        outcomes: List[BatchOutcome] = []
        for filename, data in items:
            try:
                outcomes.append(BatchOutcome(filename, result=await self.detect(data, options)))
            except (ServiceBusyError, ModelNotReadyError):
                raise
            except AppError as exc:
                outcomes.append(BatchOutcome(filename, error=exc))
        return outcomes

    # -- internals -----------------------------------------------------------------------
    async def _analyze(
        self, data: bytes, options: DetectionOptions
    ) -> Tuple[DecodedImage, DetectionResult]:
        if not self.ready:
            raise ModelNotReadyError()
        params = self._params(options)  # validate before consuming a capacity slot

        def work() -> Tuple[DecodedImage, DetectionResult]:
            image = self._decoder.decode(data)
            start = time.perf_counter()
            detections = self._detector.detect(image, params)
            elapsed_ms = (time.perf_counter() - start) * 1000
            return image, DetectionResult(image.width, image.height, detections, elapsed_ms)

        return await self._run(work)

    async def _run(self, fn: Callable[[], T]) -> T:
        """Run blocking work off the event loop, bounded by admission control and a timeout."""
        async with self._admission.slot():
            try:
                with anyio.fail_after(self._limits.timeout_s):
                    return await anyio.to_thread.run_sync(fn, abandon_on_cancel=True)
            except TimeoutError as exc:
                raise InferenceTimeoutError(
                    f"Processing exceeded {self._limits.timeout_s:g}s"
                ) from exc
            except AppError:
                raise
            except Exception as exc:
                logger.exception("Unexpected failure during inference")
                raise InferenceFailedError("Inference failed") from exc

    def _params(self, options: DetectionOptions) -> DetectionParams:
        lim = self._limits
        conf = lim.default_conf if options.conf is None else options.conf
        iou = lim.default_iou if options.iou is None else options.iou
        max_det = lim.default_max_det if options.max_det is None else options.max_det
        if not 0.0 <= conf <= 1.0:
            raise InvalidParameterError("conf must be between 0 and 1")
        if not 0.0 <= iou <= 1.0:
            raise InvalidParameterError("iou must be between 0 and 1")
        if not 1 <= max_det <= lim.max_det_limit:
            raise InvalidParameterError(f"max_det must be between 1 and {lim.max_det_limit}")
        return DetectionParams(conf, iou, max_det, self._resolve_classes(options.classes))

    def _resolve_classes(self, names: Optional[Sequence[str]]) -> Optional[Tuple[int, ...]]:
        wanted = [n.strip().lower() for n in (names or []) if n.strip()]
        if not wanted:
            return None
        index = {name.lower(): i for i, name in enumerate(self._detector.class_names)}
        unknown = sorted({n for n in wanted if n not in index})
        if unknown:
            raise InvalidParameterError(f"Unknown class name(s): {', '.join(unknown)}")
        return tuple(sorted({index[n] for n in wanted}))
