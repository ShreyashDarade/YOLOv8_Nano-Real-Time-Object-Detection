"""Command-line interface: `yolo-nano <command>`."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Optional, Sequence

from . import __version__
from .config import Config, load_config


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", help="YAML config file (see configs/default.yaml)")
    p.add_argument("--weights", help="Model weights or .yaml (default: yolov8n.pt)")
    p.add_argument("--device", help="cpu, 0, mps, ... (default: auto)")
    p.add_argument("--imgsz", type=int, help="Inference/training image size")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="yolo-nano", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("train", help="Train a model")
    _common(p)
    p.add_argument("--data", help="Dataset YAML")
    p.add_argument("--epochs", type=int)
    p.add_argument("--batch", type=int)

    p = sub.add_parser("eval", help="Evaluate on the validation split")
    _common(p)
    p.add_argument("--data", help="Dataset YAML")

    p = sub.add_parser("predict", help="Run detection on images/videos/directories")
    _common(p)
    p.add_argument("source", help="Image, video, directory or URL")
    p.add_argument("--conf", type=float)
    p.add_argument("--iou", type=float)
    p.add_argument("--no-save", action="store_true", help="Do not write annotated outputs")

    p = sub.add_parser("export", help="Export weights to ONNX, OpenVINO, TensorRT, ...")
    _common(p)
    p.add_argument("--format", dest="export_format")
    p.add_argument("--half", action="store_true", default=None)
    p.add_argument("--dynamic", action="store_true", default=None)

    p = sub.add_parser("benchmark", help="Measure inference latency and FPS")
    _common(p)
    p.add_argument("--image", help="Image to use (default: random noise)")
    p.add_argument("--runs", type=int, default=50)
    p.add_argument("--warmup", type=int, default=5)

    p = sub.add_parser("realtime", help="Live detection from webcam, video or stream")
    _common(p)
    p.add_argument("--source", help="Webcam index, video path or rtsp:// URL")
    p.add_argument("--conf", type=float)
    p.add_argument("--save", help="Write annotated video to this path")
    p.add_argument("--no-show", action="store_true", help="Headless: do not open a window")
    return parser


def overrides_from_args(args: argparse.Namespace) -> dict:
    """Map parsed CLI flags onto the nested config structure (unset flags are skipped)."""
    mapping = {
        "model": {"weights": "weights", "device": "device", "imgsz": "imgsz"},
        "train": {"data": "data", "epochs": "epochs", "batch": "batch"},
        "predict": {"conf": "conf", "iou": "iou"},
        "export": {"format": "export_format", "half": "half", "dynamic": "dynamic"},
        "realtime": {"source": "source", "save": "save"},
    }
    out: dict = {}
    for section, keys in mapping.items():
        for cfg_key, arg_name in keys.items():
            value = getattr(args, arg_name, None)
            if value is not None:
                out.setdefault(section, {})[cfg_key] = value
    if getattr(args, "no_show", False):
        out.setdefault("realtime", {})["show"] = False
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg: Config = load_config(args.config, overrides_from_args(args))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Imported here so `--help` and config errors work without heavy dependencies.
    from . import core

    if args.command == "train":
        core.train(cfg)
    elif args.command == "eval":
        print(json.dumps(core.evaluate(cfg), indent=2))
    elif args.command == "predict":
        core.predict(cfg, args.source, save=not args.no_save)
    elif args.command == "export":
        print(core.export(cfg))
    elif args.command == "benchmark":
        result = core.benchmark(cfg, args.image, args.runs, args.warmup)
        print(json.dumps(asdict(result), indent=2))
    elif args.command == "realtime":
        from . import realtime

        realtime.run(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
