import pytest

from yolo_nano.core import summarize_latencies
from yolo_nano.realtime import FPSMeter, parse_source


def test_summarize_latencies():
    r = summarize_latencies([10.0] * 19 + [30.0])
    assert r.runs == 20
    assert r.mean_ms == pytest.approx(11.0)
    assert r.p50_ms == 10.0
    assert r.p95_ms == 10.0
    assert r.fps == pytest.approx(1000 / 11.0)


def test_summarize_empty():
    with pytest.raises(ValueError):
        summarize_latencies([])


def test_parse_source():
    assert parse_source("0") == 0
    assert parse_source(2) == 2
    assert parse_source("rtsp://cam/stream") == "rtsp://cam/stream"
    assert parse_source("video.mp4") == "video.mp4"


def test_fps_meter():
    m = FPSMeter()
    assert m.tick(0.0) == 0.0
    assert m.tick(0.1) == pytest.approx(10.0)
    assert m.tick(0.2) == pytest.approx(10.0)
