"""Domain -> wire-format conversion, kept out of routes and services."""
from __future__ import annotations

from typing import Optional

from app.api.schemas import BatchItem, BBoxOut, DetectionOut, DetectResponse, ErrorBody, ImageInfo
from app.domain.models import Detection, DetectionResult
from app.services.detection_service import BatchOutcome


def detection_out(d: Detection) -> DetectionOut:
    b = d.box
    return DetectionOut(
        class_id=d.class_id,
        class_name=d.class_name,
        confidence=round(d.confidence, 4),
        bbox=BBoxOut(x1=round(b.x1, 2), y1=round(b.y1, 2), x2=round(b.x2, 2), y2=round(b.y2, 2)),
    )


def detect_response(model: str, result: DetectionResult) -> DetectResponse:
    return DetectResponse(
        model=model,
        image=ImageInfo(width=result.width, height=result.height),
        count=len(result.detections),
        inference_ms=round(result.inference_ms, 2),
        detections=[detection_out(d) for d in result.detections],
    )


def batch_item(model: str, outcome: BatchOutcome, request_id: Optional[str]) -> BatchItem:
    if outcome.error is not None:
        return BatchItem(
            filename=outcome.filename,
            status="error",
            error=ErrorBody(
                code=outcome.error.code, message=outcome.error.message, request_id=request_id
            ),
        )
    return BatchItem(
        filename=outcome.filename, status="ok", result=detect_response(model, outcome.result)
    )
