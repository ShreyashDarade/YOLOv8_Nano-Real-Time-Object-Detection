from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class BBoxOut(BaseModel):
    x1: float
    y1: float
    x2: float
    y2: float


class DetectionOut(BaseModel):
    class_id: int
    class_name: str
    confidence: float = Field(ge=0, le=1)
    bbox: BBoxOut


class ImageInfo(BaseModel):
    width: int
    height: int


class DetectResponse(BaseModel):
    model: str
    image: ImageInfo
    count: int
    inference_ms: float
    detections: List[DetectionOut]


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: Optional[str] = None


class ErrorResponse(BaseModel):
    error: ErrorBody


class BatchItem(BaseModel):
    filename: str
    status: Literal["ok", "error"]
    result: Optional[DetectResponse] = None
    error: Optional[ErrorBody] = None


class BatchResponse(BaseModel):
    total: int
    succeeded: int
    failed: int
    items: List[BatchItem]


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"


class ReadyResponse(BaseModel):
    status: Literal["ready"] = "ready"
    model: str


class LimitsOut(BaseModel):
    max_upload_bytes: int
    max_image_pixels: int
    max_batch_files: int
    max_det_limit: int
    allowed_formats: List[str]
    output_formats: List[str]


class ModelInfo(BaseModel):
    name: str
    imgsz: int
    class_count: int
    classes: List[str]
    limits: LimitsOut
