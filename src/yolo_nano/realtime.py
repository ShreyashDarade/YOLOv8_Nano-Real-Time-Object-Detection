"""Real-time detection from a webcam, video file or network stream."""
from __future__ import annotations

import time
from typing import Optional, Union

from .config import Config
from .core import load_model


def parse_source(source: Union[str, int]) -> Union[str, int]:
    """Numeric strings are webcam indices; everything else is a path/URL."""
    if isinstance(source, int):
        return source
    return int(source) if source.strip().isdigit() else source


class FPSMeter:
    """Exponential moving average of frames per second."""

    def __init__(self, alpha: float = 0.1) -> None:
        self.alpha = alpha
        self.fps = 0.0
        self._last: Optional[float] = None

    def tick(self, now: Optional[float] = None) -> float:
        now = time.perf_counter() if now is None else now
        if self._last is not None and now > self._last:
            inst = 1.0 / (now - self._last)
            self.fps = inst if self.fps == 0.0 else self.alpha * inst + (1 - self.alpha) * self.fps
        self._last = now
        return self.fps


def run(cfg: Config, max_frames: Optional[int] = None) -> int:
    """Run detection until the stream ends or 'q' is pressed. Returns frames processed."""
    import cv2

    source = parse_source(cfg.realtime.source)
    cap = cv2.VideoCapture(source)
    if not cap.isOpened():
        raise RuntimeError(f"Could not open video source: {cfg.realtime.source!r}")

    model = load_model(cfg.model.weights)
    meter = FPSMeter()
    writer = None
    frames = 0
    try:
        while max_frames is None or frames < max_frames:
            ok, frame = cap.read()
            if not ok:
                break
            result = model.predict(
                frame,
                imgsz=cfg.model.imgsz,
                conf=cfg.predict.conf,
                iou=cfg.predict.iou,
                max_det=cfg.predict.max_det,
                device=cfg.model.device,
                verbose=False,
            )[0]
            annotated = result.plot()
            fps = meter.tick()
            cv2.putText(annotated, f"{fps:.1f} FPS", (10, 30), cv2.FONT_HERSHEY_SIMPLEX,
                        1.0, (0, 255, 0), 2)

            if cfg.realtime.save:
                if writer is None:
                    h, w = annotated.shape[:2]
                    writer = cv2.VideoWriter(cfg.realtime.save, cv2.VideoWriter_fourcc(*"mp4v"),
                                             cap.get(cv2.CAP_PROP_FPS) or 30.0, (w, h))
                writer.write(annotated)
            if cfg.realtime.show:
                cv2.imshow("YOLOv8n", annotated)
                if cv2.waitKey(1) & 0xFF == ord("q"):
                    break
            frames += 1
    finally:
        cap.release()
        if writer is not None:
            writer.release()
        if cfg.realtime.show:
            cv2.destroyAllWindows()
    return frames
