import numpy as np
import pytest

from app.core.errors import ModelNotReadyError
from app.domain.models import DecodedImage, DetectionParams
from app.infrastructure.yolo_detector import YoloDetector


class _T:
    """Mimics a torch tensor's .cpu().numpy() chain."""

    def __init__(self, arr):
        self.arr = np.asarray(arr)

    def cpu(self):
        return self

    def numpy(self):
        return self.arr


class _Boxes:
    def __init__(self, xyxy, conf, cls):
        self.xyxy, self.conf, self.cls = _T(xyxy), _T(conf), _T(cls)

    def __len__(self):
        return len(self.xyxy.arr)


class _Result:
    def __init__(self, boxes):
        self.boxes = boxes


@pytest.fixture
def det():
    d = YoloDetector("weights/yolov8n.pt", "cpu", 640)
    d._names = ["person", "car"]
    return d


def test_name_is_basename(det):
    assert det.name == "yolov8n.pt"


def test_detect_before_load_raises():
    d = YoloDetector("x.pt", "cpu", 640)
    img = DecodedImage(np.zeros((4, 4, 3), np.uint8), 4, 4, "PNG")
    assert not d.ready
    with pytest.raises(ModelNotReadyError):
        d.detect(img, DetectionParams(0.25, 0.7, 10))


def test_conversion_and_clipping(det):
    result = _Result(_Boxes([[-5, 2, 120, 90], [1, 1, 5, 5]], [0.8, 0.4], [1, 0]))
    out = det._to_detections(result, width=100, height=80)
    assert [d.class_name for d in out] == ["car", "person"]
    b = out[0].box
    assert (b.x1, b.y1, b.x2, b.y2) == (0.0, 2.0, 100.0, 80.0)
    assert out[0].confidence == pytest.approx(0.8)


@pytest.mark.parametrize("boxes", [None, _Boxes(np.zeros((0, 4)), [], [])])
def test_no_boxes(det, boxes):
    assert det._to_detections(_Result(boxes), 10, 10) == []


def test_unknown_class_id_falls_back_to_string(det):
    out = det._to_detections(_Result(_Boxes([[0, 0, 1, 1]], [0.9], [7])), 10, 10)
    assert out[0].class_name == "7"


def test_passes_bgr_and_params_to_model(det):
    seen = {}

    class Model:
        def predict(self, image, **kw):
            seen["image"], seen["kw"] = image, kw
            return [_Result(None)]

    det._model = Model()
    rgb = np.zeros((2, 2, 3), np.uint8)
    rgb[..., 0] = 255  # pure red in RGB
    det.detect(DecodedImage(rgb, 2, 2, "PNG"), DetectionParams(0.3, 0.6, 5, (1, 2)))
    assert seen["image"][0, 0].tolist() == [0, 0, 255]  # BGR
    assert seen["kw"]["conf"] == 0.3 and seen["kw"]["classes"] == [1, 2]
