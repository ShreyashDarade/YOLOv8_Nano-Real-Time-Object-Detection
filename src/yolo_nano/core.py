"""Thin, testable wrappers around the Ultralytics YOLOv8 API."""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .config import Config


def load_model(weights: str) -> Any:
    """Load a YOLO model. Imported lazily so the CLI works without ultralytics installed."""
    from ultralytics import YOLO

    return YOLO(weights)


def train(cfg: Config) -> Any:
    model = load_model(cfg.model.weights)
    return model.train(
        data=cfg.train.data,
        epochs=cfg.train.epochs,
        imgsz=cfg.model.imgsz,
        batch=cfg.train.batch,
        device=cfg.model.device,
        project=cfg.train.project,
        name=cfg.train.name,
        seed=cfg.train.seed,
        patience=cfg.train.patience,
    )


def evaluate(cfg: Config) -> dict:
    """Validate on the dataset's val split and return headline metrics."""
    model = load_model(cfg.model.weights)
    metrics = model.val(data=cfg.train.data, imgsz=cfg.model.imgsz, device=cfg.model.device)
    return {
        "precision": float(metrics.box.mp),
        "recall": float(metrics.box.mr),
        "mAP50": float(metrics.box.map50),
        "mAP50-95": float(metrics.box.map),
    }


def predict(cfg: Config, source: str, save: bool = True) -> list:
    model = load_model(cfg.model.weights)
    return model.predict(
        source=source,
        imgsz=cfg.model.imgsz,
        conf=cfg.predict.conf,
        iou=cfg.predict.iou,
        max_det=cfg.predict.max_det,
        device=cfg.model.device,
        save=save,
    )


def export(cfg: Config) -> str:
    model = load_model(cfg.model.weights)
    return str(
        model.export(
            format=cfg.export.format,
            imgsz=cfg.model.imgsz,
            half=cfg.export.half,
            dynamic=cfg.export.dynamic,
            device=cfg.model.device,
        )
    )


@dataclass
class BenchmarkResult:
    runs: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    fps: float


def summarize_latencies(latencies_ms: list) -> BenchmarkResult:
    """Reduce per-frame latencies (ms) to summary statistics."""
    if not latencies_ms:
        raise ValueError("No latencies to summarize")
    ordered = sorted(latencies_ms)
    mean = statistics.fmean(ordered)
    p95_index = min(len(ordered) - 1, max(0, int(round(0.95 * len(ordered))) - 1))
    return BenchmarkResult(
        runs=len(ordered),
        mean_ms=mean,
        p50_ms=statistics.median(ordered),
        p95_ms=ordered[p95_index],
        fps=1000.0 / mean,
    )


def benchmark(
    cfg: Config, image: Optional[str] = None, runs: int = 50, warmup: int = 5
) -> BenchmarkResult:
    """Measure end-to-end single-image inference latency."""
    import numpy as np

    if runs <= 0:
        raise ValueError("runs must be > 0")
    model = load_model(cfg.model.weights)
    if image:
        if not Path(image).is_file():
            raise FileNotFoundError(image)
        frame: Any = image
    else:
        frame = np.random.default_rng(0).integers(
            0, 255, (cfg.model.imgsz, cfg.model.imgsz, 3), dtype=np.uint8
        )
    kwargs = dict(imgsz=cfg.model.imgsz, device=cfg.model.device, verbose=False)
    for _ in range(warmup):
        model.predict(frame, **kwargs)
    latencies = []
    for _ in range(runs):
        start = time.perf_counter()
        model.predict(frame, **kwargs)
        latencies.append((time.perf_counter() - start) * 1000)
    return summarize_latencies(latencies)
