FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /workspace

# CLI used by the verify service to run the image-build check through the
# mounted Docker daemon socket; curl powers the container healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY verify ./verify
COPY tests ./tests

EXPOSE 8080

CMD ["python", "-m", "app.main"]
