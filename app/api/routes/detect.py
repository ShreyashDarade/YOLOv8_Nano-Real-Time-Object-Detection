from __future__ import annotations

from typing import List, Tuple, Union

from fastapi import APIRouter, Depends, File, Query, Request, Response, UploadFile

from app.api import mappers
from app.api.deps import (
    detection_options,
    get_service,
    get_settings,
    read_upload,
    safe_filename,
)
from app.api.schemas import (
    BatchResponse,
    DetectResponse,
    ErrorResponse,
    LimitsOut,
    ModelInfo,
)
from app.core.config import Settings
from app.core.errors import AppError, TooManyFilesError
from app.services.detection_service import BatchOutcome, DetectionOptions, DetectionService

router = APIRouter(prefix="/v1", tags=["detection"])

_ERRORS = {
    400: {"model": ErrorResponse, "description": "Empty or corrupt image"},
    401: {"model": ErrorResponse, "description": "Missing/invalid API key"},
    413: {"model": ErrorResponse, "description": "Upload or image too large"},
    415: {"model": ErrorResponse, "description": "Unsupported image format"},
    422: {"model": ErrorResponse, "description": "Invalid parameters"},
    503: {"model": ErrorResponse, "description": "Model not ready or server busy (retry)"},
    504: {"model": ErrorResponse, "description": "Inference timed out"},
}


@router.get("/model", response_model=ModelInfo, summary="Model metadata and API limits")
async def model_info(
    service: DetectionService = Depends(get_service), settings: Settings = Depends(get_settings)
) -> ModelInfo:
    names = list(service.class_names)
    return ModelInfo(
        name=service.model_name,
        imgsz=settings.imgsz,
        class_count=len(names),
        classes=names,
        limits=LimitsOut(
            max_upload_bytes=settings.max_upload_bytes,
            max_image_pixels=settings.max_image_pixels,
            max_batch_files=settings.max_batch_files,
            max_det_limit=settings.max_det_limit,
            allowed_formats=settings.allowed_formats,
            output_formats=list(service.output_formats),
        ),
    )


@router.post(
    "/detect",
    response_model=DetectResponse,
    responses=_ERRORS,
    summary="Detect objects in one image",
)
async def detect(
    file: UploadFile = File(..., description="JPEG, PNG, WEBP or BMP image"),
    options: DetectionOptions = Depends(detection_options),
    service: DetectionService = Depends(get_service),
    settings: Settings = Depends(get_settings),
) -> DetectResponse:
    data = await read_upload(file, settings.max_upload_bytes)
    result = await service.detect(data, options)
    return mappers.detect_response(service.model_name, result)


@router.post(
    "/detect/batch",
    response_model=BatchResponse,
    responses=_ERRORS,
    summary="Detect objects in several images (per-file results)",
)
async def detect_batch(
    request: Request,
    files: List[UploadFile] = File(..., description="Images to process"),
    options: DetectionOptions = Depends(detection_options),
    service: DetectionService = Depends(get_service),
    settings: Settings = Depends(get_settings),
) -> BatchResponse:
    if len(files) > settings.max_batch_files:
        raise TooManyFilesError(f"At most {settings.max_batch_files} files per batch")

    # Read every upload first; unreadable ones (empty / too large) become per-file errors.
    reads: List[Tuple[str, Union[bytes, AppError]]] = []
    for upload in files:
        name = safe_filename(upload)
        try:
            reads.append((name, await read_upload(upload, settings.max_upload_bytes)))
        except AppError as exc:
            reads.append((name, exc))

    processed = iter(
        await service.detect_many([(n, d) for n, d in reads if isinstance(d, bytes)], options)
    )
    outcomes = [
        next(processed) if isinstance(d, bytes) else BatchOutcome(n, error=d) for n, d in reads
    ]
    request_id = getattr(request.state, "request_id", None)
    items = [mappers.batch_item(service.model_name, o, request_id) for o in outcomes]
    ok = sum(1 for i in items if i.status == "ok")
    return BatchResponse(total=len(items), succeeded=ok, failed=len(items) - ok, items=items)


@router.post(
    "/detect/annotated",
    responses={200: {"content": {"image/jpeg": {}, "image/png": {}}}, **_ERRORS},
    response_class=Response,
    summary="Return the image with boxes drawn on it",
)
async def detect_annotated(
    file: UploadFile = File(...),
    format: str = Query("jpeg", description="Output format: jpeg or png"),
    options: DetectionOptions = Depends(detection_options),
    service: DetectionService = Depends(get_service),
    settings: Settings = Depends(get_settings),
) -> Response:
    data = await read_upload(file, settings.max_upload_bytes)
    rendered, result = await service.annotate(data, options, format)
    return Response(
        content=rendered,
        media_type="image/png" if format.lower() == "png" else "image/jpeg",
        headers={"X-Detection-Count": str(len(result.detections))},
    )
