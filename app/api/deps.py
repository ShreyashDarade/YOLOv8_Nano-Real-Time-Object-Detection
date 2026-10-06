from __future__ import annotations

import os
from typing import List, Optional

from fastapi import Query, Request, UploadFile

from app.core.config import Settings
from app.core.errors import EmptyUploadError, PayloadTooLargeError
from app.services.detection_service import DetectionOptions, DetectionService

_CHUNK = 64 * 1024


def get_service(request: Request) -> DetectionService:
    return request.app.state.service


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def detection_options(
    conf: Optional[float] = Query(None, ge=0, le=1, description="Confidence threshold"),
    iou: Optional[float] = Query(None, ge=0, le=1, description="NMS IoU threshold"),
    max_det: Optional[int] = Query(None, ge=1, description="Max detections per image"),
    classes: Optional[List[str]] = Query(
        None, description="Only return these class names (repeat or comma-separate)"
    ),
) -> DetectionOptions:
    flat = [c for item in (classes or []) for c in item.split(",")]
    return DetectionOptions(conf=conf, iou=iou, max_det=max_det, classes=flat or None)


def safe_filename(upload: UploadFile) -> str:
    """Basename only, control characters stripped, length-capped (echoed back to clients)."""
    name = os.path.basename((upload.filename or "").replace("\\", "/"))
    name = "".join(ch for ch in name if ch.isprintable())
    return name[:255] or "unnamed"


async def read_upload(upload: UploadFile, max_bytes: int) -> bytes:
    """Read an upload in chunks, aborting as soon as it exceeds ``max_bytes``."""
    chunks, size = [], 0
    while True:
        chunk = await upload.read(_CHUNK)
        if not chunk:
            break
        size += len(chunk)
        if size > max_bytes:
            raise PayloadTooLargeError(
                f"File '{safe_filename(upload)}' exceeds the {max_bytes} byte limit"
            )
        chunks.append(chunk)
    if size == 0:
        raise EmptyUploadError(f"File '{safe_filename(upload)}' is empty")
    return b"".join(chunks)
