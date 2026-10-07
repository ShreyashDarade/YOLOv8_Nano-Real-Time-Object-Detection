.PHONY: install lint test test-integration run docker

install:
	pip install -e ".[dev,yolo]"

lint:
	ruff check app tests

test:
	pytest

test-integration:
	pytest -m integration -o addopts=""

run:
	uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --reload

docker:
	docker build -t yolo-nano-api .
