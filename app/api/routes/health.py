from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_service
from app.api.schemas import ErrorResponse, HealthResponse, ReadyResponse
from app.core.errors import ModelNotReadyError
from app.services.detection_service import DetectionService

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse, summary="Liveness probe")
async def healthz() -> HealthResponse:
    return HealthResponse()


@router.get(
    "/readyz",
    response_model=ReadyResponse,
    responses={503: {"model": ErrorResponse}},
    summary="Readiness probe (model loaded)",
)
async def readyz(service: DetectionService = Depends(get_service)) -> ReadyResponse:
    if not service.ready:
        raise ModelNotReadyError()
    return ReadyResponse(model=service.model_name)
