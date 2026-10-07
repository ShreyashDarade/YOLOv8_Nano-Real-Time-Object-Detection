"""Environment-driven settings (12-factor). All variables are prefixed ``YOLO_``."""
from __future__ import annotations

from functools import lru_cache
from typing import Annotated, List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split_csv(value):
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="YOLO_", env_file=".env", extra="ignore")

    # Model
    weights: str = "yolov8n.pt"
    device: str = "cpu"
    imgsz: int = Field(640, gt=0)

    # Inference defaults and hard limits
    default_conf: float = Field(0.25, ge=0, le=1)
    default_iou: float = Field(0.7, ge=0, le=1)
    default_max_det: int = Field(100, ge=1)
    max_det_limit: int = Field(1000, ge=1)

    # Upload limits
    max_upload_bytes: int = Field(10 * 1024 * 1024, gt=0)
    max_request_bytes: int = Field(50 * 1024 * 1024, gt=0)
    max_image_pixels: int = Field(25_000_000, gt=0)
    max_batch_files: int = Field(10, ge=1)
    allowed_formats: Annotated[List[str], NoDecode] = ["JPEG", "PNG", "WEBP", "BMP"]

    # Capacity / backpressure
    max_concurrent_inferences: int = Field(1, ge=1)
    max_pending_requests: int = Field(8, ge=0)
    inference_timeout_s: float = Field(30.0, gt=0)

    # Security / HTTP
    api_keys: Annotated[List[str], NoDecode] = []
    cors_origins: Annotated[List[str], NoDecode] = []
    docs_enabled: bool = True
    log_level: str = "INFO"

    @field_validator("allowed_formats", "api_keys", "cors_origins", mode="before")
    @classmethod
    def _csv(cls, value):
        return _split_csv(value)

    @field_validator("allowed_formats")
    @classmethod
    def _upper(cls, value):
        return [v.upper() for v in value]

    @field_validator("imgsz")
    @classmethod
    def _imgsz_multiple_of_32(cls, value):
        if value % 32:
            raise ValueError("imgsz must be a multiple of 32")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
