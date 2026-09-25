FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

COPY requirements.txt requirements-test.txt ./
RUN pip install --no-cache-dir -r requirements-test.txt

COPY app ./app
COPY tests ./tests
COPY verify ./verify

RUN mkdir -p /data && useradd -r -u 10001 archivist \
    && chown -R archivist:archivist /data /srv
USER archivist

ARG APP_PORT=8080
ENV APP_PORT=${APP_PORT} \
    HEALTH_PATH=/healthz \
    DB_PATH=/data/archive.db \
    ALLOW_FAILPOINT=1
EXPOSE ${APP_PORT}

HEALTHCHECK --interval=3s --timeout=3s --start-period=5s --retries=10 \
    CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('APP_PORT','8080')+os.environ.get('HEALTH_PATH','/healthz'), timeout=2).status==200 else 1)"

CMD ["python", "-m", "app.server"]
