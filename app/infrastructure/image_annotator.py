from __future__ import annotations

import io
from typing import Sequence

from PIL import Image, ImageDraw

from app.core.errors import InvalidParameterError
from app.domain.interfaces import ImageAnnotator
from app.domain.models import DecodedImage, Detection

_PALETTE = [
    (230, 25, 75), (60, 180, 75), (255, 178, 0), (0, 130, 200), (245, 130, 48),
    (145, 30, 180), (70, 240, 240), (240, 50, 230), (210, 245, 60), (0, 128, 128),
]
_FORMATS = {"JPEG": "JPEG", "JPG": "JPEG", "PNG": "PNG"}


class PillowImageAnnotator(ImageAnnotator):
    @property
    def supported_formats(self) -> Sequence[str]:
        return ["jpeg", "png"]

    def render(self, image: DecodedImage, detections: Sequence[Detection], fmt: str) -> bytes:
        pil_format = _FORMATS.get(fmt.upper())
        if pil_format is None:
            raise InvalidParameterError(
                f"Unsupported output format {fmt!r}; use one of {', '.join(self.supported_formats)}"
            )
        canvas = Image.fromarray(image.pixels, "RGB")
        draw = ImageDraw.Draw(canvas)
        for det in detections:
            color = _PALETTE[det.class_id % len(_PALETTE)]
            b = det.box
            line_width = max(2, image.width // 300)
            draw.rectangle([b.x1, b.y1, b.x2, b.y2], outline=color, width=line_width)
            label = f"{det.class_name} {det.confidence:.2f}"
            left, top, right, bottom = draw.textbbox((0, 0), label)
            text_w, text_h = right - left, bottom - top
            y0 = max(0.0, b.y1 - text_h - 4)
            draw.rectangle([b.x1, y0, b.x1 + text_w + 4, y0 + text_h + 4], fill=color)
            draw.text((b.x1 + 2, y0 + 1), label, fill=(255, 255, 255))
        out = io.BytesIO()
        canvas.save(out, format=pil_format, **({"quality": 90} if pil_format == "JPEG" else {}))
        return out.getvalue()
