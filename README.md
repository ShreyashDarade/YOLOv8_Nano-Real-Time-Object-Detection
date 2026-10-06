# YOLOv8 Nano – Real-Time Object Detection

A small, production-style toolkit around [Ultralytics YOLOv8n](https://docs.ultralytics.com/models/yolov8/)
for training, evaluating, benchmarking, exporting and running real-time object detection from a
webcam, video file or network stream.

[![CI](https://github.com/ShreyashDarade/YOLOv8_Nano-Real-Time-Object-Detection/actions/workflows/ci.yml/badge.svg)](https://github.com/ShreyashDarade/YOLOv8_Nano-Real-Time-Object-Detection/actions/workflows/ci.yml)

## Features

- **One CLI** (`yolo-nano`) for `train`, `eval`, `predict`, `export`, `benchmark` and `realtime`.
- **Config-driven**: a validated YAML config (`configs/default.yaml`) with CLI flags taking precedence.
- **Real-time inference** with an FPS overlay, headless mode and annotated-video recording.
- **Latency benchmarking**: mean / p50 / p95 latency and FPS on your hardware.
- **Export** to ONNX, OpenVINO, TensorRT, TFLite and more for edge deployment.
- **Tested and linted**, with CI on every push.

## Project layout

```
.
├── src/yolo_nano/
│   ├── cli.py        # argparse CLI and dispatch
│   ├── config.py     # typed config, YAML loading, validation
│   ├── core.py       # train / evaluate / predict / export / benchmark
│   └── realtime.py   # webcam / video / stream loop with FPS meter
├── configs/default.yaml
├── notebooks/YOLOV8.ipynb   # original exploratory notebook
├── tests/
├── .github/workflows/ci.yml
└── pyproject.toml
```

## Installation

```bash
git clone https://github.com/ShreyashDarade/YOLOv8_Nano-Real-Time-Object-Detection.git
cd YOLOv8_Nano-Real-Time-Object-Detection
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.9+. A GPU is optional; YOLOv8n runs on CPU. For GPU, install the PyTorch build
matching your CUDA version first (see [pytorch.org](https://pytorch.org/get-started/locally/)).

## Usage

```bash
# Live detection from the default webcam (press q to quit)
yolo-nano realtime

# Video file or RTSP stream, saved headless to disk
yolo-nano realtime --source video.mp4 --no-show --save out.mp4
yolo-nano realtime --source rtsp://user:pass@host/stream

# Detect on images, folders or videos (results go to runs/detect/)
yolo-nano predict path/to/images --conf 0.4

# Train on COCO128 (auto-downloaded) and evaluate
yolo-nano train --data coco128.yaml --epochs 50 --batch 16
yolo-nano eval --weights runs/yolov8n/weights/best.pt

# Measure latency / FPS on this machine
yolo-nano benchmark --device cpu --runs 100

# Export for deployment
yolo-nano export --weights runs/yolov8n/weights/best.pt --format onnx
```

Run `yolo-nano <command> --help` for all options. The same operations are available via `make`
(`make test`, `make lint`, `make benchmark`, ...).

### Configuration

Settings are resolved in this order, later entries winning: built-in defaults → `--config file.yaml`
→ CLI flags. Unknown keys and invalid values (e.g. an `imgsz` that is not a multiple of 32) fail
fast with a clear error. See [`configs/default.yaml`](configs/default.yaml) for every option.

To train on your own data, point `train.data` at a standard YOLO dataset YAML:

```yaml
# my_dataset.yaml
path: datasets/my_data
train: images/train
val: images/val
names:
  0: cat
  1: dog
```

### Python API

```python
from yolo_nano.config import load_config
from yolo_nano import core

cfg = load_config("configs/default.yaml", {"model": {"device": "cpu"}})
print(core.benchmark(cfg, runs=20))
```

## Development

```bash
make install   # editable install with dev tools
make lint      # ruff
make test      # pytest (no model download or GPU needed)
```

Unit tests cover configuration, CLI wiring and the benchmarking / FPS maths. Model-backed commands
download `yolov8n.pt` on first use.

## Notes

- Benchmark numbers vary widely by hardware, so measure on your own target device rather than
  relying on published figures.
- `runs/`, datasets and weight files are git-ignored.

## Acknowledgements

Built on [Ultralytics YOLOv8](https://github.com/ultralytics/ultralytics). Note that Ultralytics is
licensed under AGPL-3.0 (with an enterprise option); check its terms before commercial use. This
repository does not yet declare its own license.
