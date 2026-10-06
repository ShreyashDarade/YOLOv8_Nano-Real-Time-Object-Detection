"""Typed configuration loaded from YAML with CLI overrides."""
from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, Optional, Union

import yaml


@dataclass
class ModelConfig:
    weights: str = "yolov8n.pt"
    device: Optional[str] = None
    imgsz: int = 640


@dataclass
class TrainConfig:
    data: str = "coco128.yaml"
    epochs: int = 50
    batch: int = 16
    project: str = "runs"
    name: str = "yolov8n"
    seed: int = 0
    patience: int = 20


@dataclass
class PredictConfig:
    conf: float = 0.25
    iou: float = 0.7
    max_det: int = 300


@dataclass
class ExportConfig:
    format: str = "onnx"
    half: bool = False
    dynamic: bool = False


@dataclass
class RealtimeConfig:
    source: str = "0"
    show: bool = True
    save: Optional[str] = None


@dataclass
class Config:
    model: ModelConfig = field(default_factory=ModelConfig)
    train: TrainConfig = field(default_factory=TrainConfig)
    predict: PredictConfig = field(default_factory=PredictConfig)
    export: ExportConfig = field(default_factory=ExportConfig)
    realtime: RealtimeConfig = field(default_factory=RealtimeConfig)

    def validate(self) -> None:
        if self.model.imgsz <= 0 or self.model.imgsz % 32:
            raise ValueError(
                f"model.imgsz must be a positive multiple of 32, got {self.model.imgsz}"
            )
        if self.train.epochs <= 0:
            raise ValueError("train.epochs must be > 0")
        if self.train.batch == 0 or self.train.batch < -1:
            raise ValueError("train.batch must be > 0 (or -1 for auto)")
        for name in ("conf", "iou"):
            value = getattr(self.predict, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"predict.{name} must be in [0, 1], got {value}")


def _merge(obj: Any, data: dict, path: str = "") -> None:
    """Recursively copy `data` onto dataclass `obj`, rejecting unknown keys."""
    known = {f.name for f in fields(obj)}
    for key, value in data.items():
        if key not in known:
            raise ValueError(f"Unknown config key: {path}{key}")
        current = getattr(obj, key)
        if is_dataclass(current):
            if not isinstance(value, dict):
                raise ValueError(f"Config section '{path}{key}' must be a mapping")
            _merge(current, value, f"{path}{key}.")
        else:
            if value is not None and current is not None:
                value = type(current)(value)
            setattr(obj, key, value)


def load_config(path: Union[str, Path, None] = None, overrides: Optional[dict] = None) -> Config:
    """Load defaults, then a YAML file, then a nested `overrides` dict."""
    cfg = Config()
    if path is not None:
        with open(path, encoding="utf-8") as fh:
            _merge(cfg, yaml.safe_load(fh) or {})
    if overrides:
        _merge(cfg, overrides)
    cfg.validate()
    return cfg
