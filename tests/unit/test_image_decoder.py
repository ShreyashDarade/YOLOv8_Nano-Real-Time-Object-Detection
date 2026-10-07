import io

import pytest
from PIL import Image

from app.core.errors import (
    EmptyUploadError,
    ImageTooLargeError,
    InvalidImageError,
    UnsupportedImageFormatError,
)
from app.infrastructure.image_decoder import PillowImageDecoder
from tests.conftest import image_bytes


@pytest.fixture
def decoder():
    return PillowImageDecoder(["JPEG", "PNG", "WEBP", "BMP"], max_pixels=10_000)


@pytest.mark.parametrize("fmt", ["PNG", "JPEG", "WEBP", "BMP"])
def test_decodes_supported_formats(decoder, fmt):
    img = decoder.decode(image_bytes(fmt, size=(40, 30)))
    assert (img.width, img.height) == (40, 30)
    assert img.pixels.shape == (30, 40, 3)
    assert img.format == fmt


@pytest.mark.parametrize("mode", ["RGBA", "L", "P", "1"])
def test_normalises_color_modes_to_rgb(decoder, mode):
    img = decoder.decode(image_bytes("PNG", size=(10, 10), mode=mode))
    assert img.pixels.shape == (10, 10, 3)


def test_applies_exif_orientation(decoder):
    src = Image.new("RGB", (40, 20), "red")
    exif = Image.Exif()
    exif[0x0112] = 6  # rotate 90 CW when displayed
    buf = io.BytesIO()
    src.save(buf, format="JPEG", exif=exif)
    img = decoder.decode(buf.getvalue())
    assert (img.width, img.height) == (20, 40)


def test_empty_upload(decoder):
    with pytest.raises(EmptyUploadError):
        decoder.decode(b"")


@pytest.mark.parametrize("junk", [b"not an image", b"\x89PNG\r\n\x1a\n garbage", b"\x00" * 64])
def test_garbage_is_invalid_image(decoder, junk):
    with pytest.raises(InvalidImageError):
        decoder.decode(junk)


def test_truncated_image_is_invalid(decoder):
    data = image_bytes("PNG", size=(80, 80))
    with pytest.raises(InvalidImageError):
        decoder.decode(data[: len(data) // 2])


def test_disallowed_format_is_415(decoder):
    with pytest.raises(UnsupportedImageFormatError):
        decoder.decode(image_bytes("GIF", size=(8, 8), mode="P"))


def test_pixel_budget_enforced_from_header(decoder):
    with pytest.raises(ImageTooLargeError):
        decoder.decode(image_bytes("PNG", size=(101, 100)))  # 10_100 > 10_000


def test_pixel_budget_boundary_is_inclusive(decoder):
    assert decoder.decode(image_bytes("PNG", size=(100, 100))).width == 100


def test_decompression_bomb_error_mapped(decoder, monkeypatch):
    def boom(*_a, **_k):
        raise Image.DecompressionBombError("bomb")

    monkeypatch.setattr(Image, "open", boom)
    with pytest.raises(ImageTooLargeError):
        decoder.decode(b"x")


def test_one_pixel_image(decoder):
    assert decoder.decode(image_bytes("PNG", size=(1, 1))).pixels.shape == (1, 1, 3)
