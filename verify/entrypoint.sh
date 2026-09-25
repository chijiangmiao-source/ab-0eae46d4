#!/bin/sh
# verify container entrypoint:
#   1. code tests (pytest)
#   2. image build check (Docker CLI against the mounted daemon socket)
#   3. archive API smoke, including a real mid-rotation crash + recovery
# Exits non-zero if any stage fails.
set -eu

cd /workspace

echo "==================================================================="
echo "[verify] stage 0: tooling"
docker version --format 'docker client {{.Client.Version}}'
docker compose version

echo "==================================================================="
echo "[verify] stage 1: code tests (pytest)"
python -m pytest -q

echo "==================================================================="
echo "[verify] stage 2: image build check"
docker compose -f compose.yaml build archive

echo "==================================================================="
echo "[verify] stage 3: archive API smoke (crash -> restart -> recover)"
# Archive container is a compose sibling on the shared project network; wait
# for its configurable health endpoint first.
HEALTH_PATH="${HEALTH_PATH:-/healthz}"
SMOKE_BASE_URL="${SMOKE_BASE_URL:-http://archive:8080}"
i=0
while [ "$i" -lt 60 ]; do
  if python -c "
import os, urllib.request, sys
try:
    r = urllib.request.urlopen('$SMOKE_BASE_URL$HEALTH_PATH', timeout=2)
    sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
"; then
    echo "[verify] archive is healthy"
    break
  fi
  i=$((i + 1))
  sleep 2
done
if [ "$i" -ge 60 ]; then
  echo "[verify] archive never became healthy"
  docker compose -f compose.yaml ps
  docker compose -f compose.yaml logs --tail=100 archive || true
  exit 1
fi

python verify/smoke.py

echo "==================================================================="
echo "[verify] ALL STAGES PASSED"
