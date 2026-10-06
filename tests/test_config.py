import pytest

from yolo_nano.config import load_config


def test_defaults():
    cfg = load_config()
    assert cfg.model.weights == "yolov8n.pt"
    assert cfg.realtime.show is True


def test_default_yaml_matches_dataclass_defaults():
    assert load_config("configs/default.yaml") == load_config()


def test_overrides_win_over_file(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("train:\n  epochs: 5\npredict:\n  conf: 0.5\n")
    cfg = load_config(f, {"train": {"epochs": 7}})
    assert cfg.train.epochs == 7
    assert cfg.predict.conf == 0.5


def test_unknown_key_rejected(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("train:\n  epohcs: 5\n")
    with pytest.raises(ValueError, match="train.epohcs"):
        load_config(f)


@pytest.mark.parametrize(
    "overrides",
    [{"model": {"imgsz": 100}}, {"train": {"epochs": 0}}, {"predict": {"conf": 1.5}}],
)
def test_validation(overrides):
    with pytest.raises(ValueError):
        load_config(overrides=overrides)
