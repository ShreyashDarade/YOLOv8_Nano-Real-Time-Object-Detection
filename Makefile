.PHONY: install lint test train eval export benchmark realtime

install:
	pip install -e ".[dev]"

lint:
	ruff check src tests

test:
	pytest

train:
	yolo-nano train --config configs/default.yaml

eval:
	yolo-nano eval --config configs/default.yaml

export:
	yolo-nano export --config configs/default.yaml

benchmark:
	yolo-nano benchmark --config configs/default.yaml

realtime:
	yolo-nano realtime --config configs/default.yaml
