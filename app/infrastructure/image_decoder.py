from __future__ import annotations

import io
from typing import Iterable

import numpy as np
from PIL import Image, ImageOps, UnidentifiedImageError

from app.core.errors import (
    EmptyUploadError,
    ImageTooLargeError,
    InvalidImageError,
    UnsupportedImageFormatError,
)
from app.domain.interfaces import ImageDecoder
from app.domain.models import DecodedImage


class PillowImageDecoder(ImageDecoder):
    """Validates untrusted bytes before decoding pixels.

    Order matters: the format allow-list and pixel budget are checked from the image
    *header*, before ``load()`` allocates memory, so decompression bombs are rejected cheaply.
    Handles EXIF rotation, alpha/palette/greyscale modes, and truncated/corrupt files.
    """

    def __init__(self, allowed_formats: Iterable[str], max_pixels: int) -> None:
        self._allowed = {f.upper() for f in allowed_formats}
        self._max_pixels = max_pixels

    def decode(self, data: bytes) -> DecodedImage:
        if not data:
            raise EmptyUploadError("Uploaded file is empty")
        try:
            with Image.open(io.BytesIO(data)) as img:
                fmt = (img.format or "").upper()
                if fmt not in self._allowed:
                    raise UnsupportedImageFormatError(
                        f"Unsupported image format {fmt or 'unknown'!r}; "
                        f"allowed: {', '.join(sorted(self._allowed))}"
                    )
                width, height = img.size
                if width < 1 or height < 1:
                    raise InvalidImageError("Image has no pixels")
                if width * height > self._max_pixels:
                    raise ImageTooLargeError(
                        f"Image is {width}x{height}; limit is {self._max_pixels} pixels"
                    )
                img.load()
                rgb = ImageOps.exif_transpose(img).convert("RGB")
        except (UnsupportedImageFormatError, ImageTooLargeError, InvalidImageError):
            raise
        except Image.DecompressionBombError as exc:
            raise ImageTooLargeError("Image exceeds the decompression safety limit") from exc
        except (UnidentifiedImageError, OSError, SyntaxError, ValueError, EOFError) as exc:
            raise InvalidImageError("File is not a valid or complete image") from exc

        pixels = np.ascontiguousarray(np.asarray(rgb, dtype=np.uint8))
        height, width = pixels.shape[:2]
        return DecodedImage(pixels=pixels, width=width, height=height, format=fmt)
