FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    YOLO_CONFIG_DIR=/tmp/Ultralytics \
    HOME=/home/app

# Runtime libs needed by OpenCV (pulled in by ultralytics).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user (uid 1000).
RUN useradd -m -u 1000 app
WORKDIR /home/app/code

# CPU-only PyTorch keeps the image small. Dependencies first for layer caching.
RUN pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install ".[yolo]"

# Bake the weights into the image so cold starts never depend on a download.
RUN python -c "from ultralytics import YOLO; YOLO('yolov8n.pt')" \
    && mv yolov8n.pt /home/app/yolov8n.pt \
    && chown -R app:app /home/app

USER app
ENV YOLO_WEIGHTS=/home/app/yolov8n.pt \
    YOLO_DEVICE=cpu \
    PORT=7860
EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ['PORT'], timeout=3)"

CMD ["sh", "-c", "uvicorn app.main:create_app --factory --host 0.0.0.0 --port ${PORT} --proxy-headers"]
