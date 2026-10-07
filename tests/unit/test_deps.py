import io

import pytest
from starlette.datastructures import UploadFile

from app.api.deps import read_upload, safe_filename
from app.core.errors import EmptyUploadError, PayloadTooLargeError


def upload(data=b"", name="a.png"):
    return UploadFile(io.BytesIO(data), filename=name)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("a.png", "a.png"), ("../../etc/passwd", "passwd"), ("C:\\x\\y.png", "y.png"),
        ("we\x00ird\n.png", "weird.png"), ("", "unnamed"), (None, "unnamed"), ("a" * 400, "a" * 255),
        ("/", "unnamed"),
    ],
)
def test_safe_filename(raw, expected):
    assert safe_filename(UploadFile(io.BytesIO(b""), filename=raw)) == expected


async def test_read_upload_exact_limit_ok_one_over_rejected():
    assert await read_upload(upload(b"x" * 100), 100) == b"x" * 100
    with pytest.raises(PayloadTooLargeError):
        await read_upload(upload(b"x" * 101), 100)


async def test_read_upload_spanning_multiple_chunks():
    data = b"y" * (64 * 1024 * 3 + 5)
    assert await read_upload(upload(data), len(data)) == data


async def test_read_upload_empty():
    with pytest.raises(EmptyUploadError):
        await read_upload(upload(b""), 100)
