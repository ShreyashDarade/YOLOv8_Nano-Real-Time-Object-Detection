"""Application error hierarchy.

Every error carries an HTTP status and a stable machine-readable ``code`` so clients can
branch on it without parsing messages. Raising these from any layer yields a uniform
JSON error envelope (see ``app.api.error_handlers``).
"""
from __future__ import annotations

from typing import Optional


class AppError(Exception):
    status_code = 500
    code = "internal_error"

    def __init__(self, message: str, *, headers: Optional[dict] = None) -> None:
        super().__init__(message)
        self.message = message
        self.headers = headers or {}


class UnauthorizedError(AppError):
    status_code = 401
    code = "unauthorized"

    def __init__(self, message: str = "Unauthorized"):
        super().__init__(message, headers={"WWW-Authenticate": "Bearer"})


class InvalidParameterError(AppError):
    status_code = 422
    code = "invalid_parameter"


class EmptyUploadError(AppError):
    status_code = 400
    code = "empty_upload"


class InvalidImageError(AppError):
    status_code = 400
    code = "invalid_image"


class UnsupportedImageFormatError(AppError):
    status_code = 415
    code = "unsupported_image_format"


class PayloadTooLargeError(AppError):
    status_code = 413
    code = "payload_too_large"


class ImageTooLargeError(AppError):
    status_code = 413
    code = "image_too_large"


class TooManyFilesError(AppError):
    status_code = 413
    code = "too_many_files"


class ServiceBusyError(AppError):
    status_code = 503
    code = "service_busy"

    def __init__(self, message: str = "Server is busy, retry shortly", retry_after: int = 1):
        super().__init__(message, headers={"Retry-After": str(retry_after)})


class ModelNotReadyError(AppError):
    status_code = 503
    code = "model_not_ready"

    def __init__(self, message: str = "Model is not loaded yet"):
        super().__init__(message, headers={"Retry-After": "5"})


class InferenceTimeoutError(AppError):
    status_code = 504
    code = "inference_timeout"


class InferenceFailedError(AppError):
    status_code = 500
    code = "inference_failed"
