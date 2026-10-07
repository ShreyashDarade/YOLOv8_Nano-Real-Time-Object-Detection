from __future__ import annotations

import logging
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.errors import AppError

logger = logging.getLogger(__name__)


def _envelope(request: Request, status: int, code: str, message: str, headers=None) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    response = JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers=headers,
    )
    if request_id:
        response.headers["X-Request-ID"] = request_id
    return response


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        return _envelope(request, exc.status_code, exc.code, exc.message, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Report location + reason only; never echo submitted values back.
        parts = [
            f"{'.'.join(str(p) for p in e['loc'] if p != 'body')}: {e['msg']}"
            for e in exc.errors()[:5]
        ]
        return _envelope(request, 422, "validation_error", "; ".join(parts) or "Invalid request")

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        try:
            phrase = HTTPStatus(exc.status_code).phrase
        except ValueError:
            phrase = "Error"
        code = phrase.lower().replace(" ", "_")
        return _envelope(request, exc.status_code, code, str(exc.detail), exc.headers)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return _envelope(request, 500, "internal_error", "Internal server error")
