from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.error_handlers import install_error_handlers
from app.api.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from app.api.routes import detect, health
from app.api.security import require_api_key
from app.container import build_service
from app.core.config import Settings, get_settings
from app.services.detection_service import DetectionService
from app.services.model_loader import ModelLoader


def create_app(
    settings: Optional[Settings] = None, service: Optional[DetectionService] = None
) -> FastAPI:
    """App factory. ``service`` can be injected (tests, alternative backends)."""
    settings = settings or get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    service = service or build_service(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        loader = ModelLoader(service.lifecycle)
        task = asyncio.create_task(loader.run())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    app = FastAPI(
        title="YOLOv8 Nano Detection API",
        version=__version__,
        description="Object detection over HTTP.",
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.service = service

    install_error_handlers(app)
    app.include_router(health.router)
    app.include_router(detect.router, dependencies=[Depends(require_api_key)])

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware, allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST"], allow_headers=["*"], expose_headers=["X-Request-ID"],
        )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(RequestContextMiddleware)  # outermost: sees every request
    return app

