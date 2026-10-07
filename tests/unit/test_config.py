import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_defaults():
    s = Settings(_env_file=None)
    assert s.weights == "yolov8n.pt"
    assert s.api_keys == [] and s.cors_origins == []
    assert s.allowed_formats == ["JPEG", "PNG", "WEBP", "BMP"]


def test_csv_env_parsing_and_normalisation(monkeypatch):
    monkeypatch.setenv("YOLO_API_KEYS", " a , b ,,")
    monkeypatch.setenv("YOLO_ALLOWED_FORMATS", "jpeg,png")
    monkeypatch.setenv("YOLO_CORS_ORIGINS", "https://x.test")
    s = Settings(_env_file=None)
    assert s.api_keys == ["a", "b"]
    assert s.allowed_formats == ["JPEG", "PNG"]
    assert s.cors_origins == ["https://x.test"]


@pytest.mark.parametrize(
    "bad", [{"imgsz": 100}, {"imgsz": 0}, {"default_conf": 1.5}, {"max_upload_bytes": 0},
            {"max_concurrent_inferences": 0}, {"inference_timeout_s": 0}],
)
def test_invalid_settings_rejected(bad):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **bad)
