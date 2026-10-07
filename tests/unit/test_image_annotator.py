import io

import numpy as np
import pytest
from PIL import Image

from app.core.errors import InvalidParameterError
from app.domain.models import BoundingBox, DecodedImage, Detection
from app.infrastructure.image_annotator import PillowImageAnnotator


@pytest.fixture
def image():
    return DecodedImage(np.full((60, 80, 3), 255, dtype=np.uint8), 80, 60, "PNG")


@pytest.mark.parametrize("fmt,expected", [("jpeg", "JPEG"), ("PNG", "PNG"), ("jpg", "JPEG")])
def test_renders_decodable_image_of_same_size(image, fmt, expected):
    dets = [Detection(0, "person", 0.91, BoundingBox(5, 5, 40, 50))]
    out = PillowImageAnnotator().render(image, dets, fmt)
    with Image.open(io.BytesIO(out)) as rendered:
        assert rendered.format == expected
        assert rendered.size == (80, 60)


def test_boxes_are_actually_drawn(image):
    dets = [Detection(0, "person", 0.9, BoundingBox(10, 20, 60, 55))]
    out = PillowImageAnnotator().render(image, dets, "png")
    pixels = np.asarray(Image.open(io.BytesIO(out)).convert("RGB"))
    assert (pixels != 255).any()


def test_no_detections_leaves_image_untouched(image):
    out = PillowImageAnnotator().render(image, [], "png")
    assert (np.asarray(Image.open(io.BytesIO(out)).convert("RGB")) == 255).all()


def test_box_at_top_edge_and_degenerate_box_do_not_crash(image):
    dets = [
        Detection(1, "car", 0.5, BoundingBox(0, 0, 80, 60)),
        Detection(2, "dog", 0.5, BoundingBox(10, 10, 10, 10)),
    ]
    assert PillowImageAnnotator().render(image, dets, "jpeg")


def test_unsupported_format(image):
    with pytest.raises(InvalidParameterError):
        PillowImageAnnotator().render(image, [], "gif")
