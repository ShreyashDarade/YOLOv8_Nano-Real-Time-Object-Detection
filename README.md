# YOLOv8 Nano Detection API

A backend-only HTTP API for object detection with [YOLOv8n](https://docs.ultralytics.com/models/yolov8/).
Upload an image, get back typed JSON detections (or the image with boxes drawn on it). No UI, no admin
panel: just a hardened service with predictable errors.

[![CI](https://github.com/ShreyashDarade/YOLOv8_Nano-Real-Time-Object-Detection/actions/workflows/ci.yml/badge.svg)](https://github.com/ShreyashDarade/YOLOv8_Nano-Real-Time-Object-Detection/actions/workflows/ci.yml)

## Quick start

```bash
pip install -e ".[yolo]"                     # add ,dev for tests
uvicorn app.main:create_app --factory --port 8000

curl -F file=@photo.jpg "http://localhost:8000/v1/detect?conf=0.4&classes=person,car"
```

Or with Docker (CPU, weights baked in, non-root, listens on `$PORT`, default 7860):

```bash
docker build -t yolo-nano-api . && docker run -p 7860:7860 yolo-nano-api
```

Interactive docs: `/docs` (disable with `YOLO_DOCS_ENABLED=false`).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness: process is up |
| GET | `/readyz` | Readiness: model loaded (503 until then) |
| GET | `/v1/model` | Model name, class list and the server's limits |
| POST | `/v1/detect` | Detect in one image (`multipart` field `file`) |
| POST | `/v1/detect/batch` | Detect in several images (`files`), per-file results |
| POST | `/v1/detect/annotated` | Returns the image (JPEG/PNG) with boxes drawn |

Query parameters on every detect endpoint: `conf` (0-1), `iou` (0-1), `max_det` (1..limit) and `classes`
(class names, repeated or comma-separated, case-insensitive). `/annotated` also takes `format=jpeg|png`.

```jsonc
// POST /v1/detect
{
  "model": "yolov8n.pt",
  "image": {"width": 810, "height": 1080},
  "count": 1,
  "inference_ms": 155.93,
  "detections": [
    {"class_id": 5, "class_name": "bus", "confidence": 0.8734,
     "bbox": {"x1": 22.87, "y1": 231.28, "x2": 805.0, "y2": 756.84}}   // pixels, original image
  ]
}
```

Batch returns `200` with `total/succeeded/failed` and one item per file (`status: ok|error`), in upload
order, so one corrupt image does not fail the others.

### Errors

Every error uses one envelope, and `code` is stable for clients to branch on:

```json
{"error": {"code": "invalid_image", "message": "File is not a valid or complete image", "request_id": "..."}}
```

| Status | `code` | When |
|---|---|---|
| 400 | `empty_upload`, `invalid_image` | Zero bytes; corrupt/truncated/not an image |
| 401 | `unauthorized` | API keys are configured and none/wrong was sent |
| 413 | `payload_too_large`, `image_too_large`, `too_many_files` | File/request over byte limit; over pixel budget; too many batch files |
| 415 | `unsupported_image_format` | Real format (not the filename) is not allowed, e.g. GIF |
| 422 | `validation_error`, `invalid_parameter` | Bad query/form input; unknown class name |
| 503 | `model_not_ready`, `service_busy` | Model still loading; queue full. Both send `Retry-After` |
| 504 | `inference_timeout` | Processing exceeded `YOLO_INFERENCE_TIMEOUT_S` |
| 500 | `inference_failed`, `internal_error` | Unexpected failure; details are logged, never returned |

Every response carries `X-Request-ID` (a valid client-supplied one is echoed, anything else is replaced).

## Edge cases handled

- **Untrusted images**: format is detected from content, not extension or `Content-Type`; format allow-list
  and pixel budget are checked from the header *before* decoding (decompression-bomb safe); EXIF rotation
  applied; RGBA/palette/greyscale normalised; truncated or garbage files rejected cleanly; 1x1 images work.
- **Size limits at three levels**: whole request (also for chunked bodies with no `Content-Length`), each
  file (streamed, aborts early), and pixels per image.
- **Backpressure**: bounded concurrency plus a bounded queue; overload returns a fast, retryable 503
  instead of growing latency and memory. Inference runs off the event loop with a timeout.
- **Self-healing startup**: the server boots immediately; model loading retries with exponential backoff
  and `/readyz` reflects the state, so a transient weights download failure doesn't need a restart.
- **Batch**: per-file errors, ordering preserved, capped file count, filenames sanitised (basename only,
  control characters removed, length-capped).
- **Auth**: optional API keys via `X-API-Key` or `Authorization: Bearer`, constant-time comparison;
  probes stay open. CORS is closed unless origins are configured.

## Configuration

Environment variables, all prefixed `YOLO_` (a `.env` file also works). List values are comma-separated.

| Variable | Default | Meaning |
|---|---|---|
| `WEIGHTS` / `DEVICE` / `IMGSZ` | `yolov8n.pt` / `cpu` / `640` | Model path, device, input size (multiple of 32) |
| `DEFAULT_CONF` / `DEFAULT_IOU` / `DEFAULT_MAX_DET` | `0.25` / `0.7` / `100` | Defaults when a request omits them |
| `MAX_DET_LIMIT` | `1000` | Upper bound for `max_det` |
| `MAX_UPLOAD_BYTES` | 10 MiB | Per file |
| `MAX_REQUEST_BYTES` | 50 MiB | Whole request body |
| `MAX_IMAGE_PIXELS` | 25,000,000 | Width x height budget |
| `MAX_BATCH_FILES` | `10` | Files per batch call |
| `ALLOWED_FORMATS` | `JPEG,PNG,WEBP,BMP` | Accepted input formats |
| `MAX_CONCURRENT_INFERENCES` / `MAX_PENDING_REQUESTS` | `1` / `8` | Parallel work / queue depth |
| `INFERENCE_TIMEOUT_S` | `30` | Per-request processing timeout |
| `API_KEYS` | *(empty = open)* | Accepted keys |
| `CORS_ORIGINS` | *(empty = none)* | Allowed browser origins |
| `DOCS_ENABLED` / `LOG_LEVEL` | `true` / `INFO` | Swagger UI; log level |

Note: on timeout the request is answered with 504 but the worker thread cannot be force-killed, so keep
`MAX_PENDING_REQUESTS` modest. Run several worker processes (`--workers N`) to scale beyond one model copy.

## Architecture (SOLID)

```
app/
├── domain/          models.py, interfaces.py     pure types + abstractions (no framework imports)
├── services/        detection_service.py         use-case orchestration
│                    admission.py, model_loader.py
├── infrastructure/  yolo_detector.py             Ultralytics adapter
│                    image_decoder.py, image_annotator.py   Pillow adapters
├── api/             routes/, schemas.py, mappers.py, middleware.py, security.py, error_handlers.py
├── core/            config.py, errors.py
├── container.py     composition root: the only place concrete classes are chosen
└── main.py          create_app() factory
```

- **Single responsibility**: decoding, annotating, inference, admission control, model loading, auth,
  body limits and response mapping each live in their own small unit.
- **Open/closed**: add a new model backend or image codec by implementing an interface; no service or route
  changes.
- **Liskov**: tests run the whole API against a `FakeDetector` that is a drop-in `Detector`.
- **Interface segregation**: `Detector`, `ModelLifecycle`, `ImageDecoder` and `ImageAnnotator` are separate,
  minimal contracts.
- **Dependency inversion**: `DetectionService` depends only on those abstractions; `container.py` wires the
  concrete YOLO/Pillow classes, and `create_app(settings, service)` accepts any service.

## Tests

```bash
pip install -e ".[dev]"
pytest                                          # ~125 tests, no PyTorch or weights needed
pip install -e ".[yolo]" && pytest -m integration -o addopts=""   # real-model checks
ruff check app tests
```

`tests/unit` covers each component, `tests/api` exercises every endpoint and failure mode over ASGI, and
`tests/integration` runs the real model (odd image sizes, class filtering).

## License / acknowledgements

Built on [Ultralytics YOLOv8](https://github.com/ultralytics/ultralytics), which is AGPL-3.0 (enterprise
licence available); check its terms before commercial use. This repository does not yet declare its own
licence.
