"""Verify orchestrator.

Runs, in order, and exits non-zero if anything fails:

  1. Python test suite (pytest)
  2. Image build check (real ``docker build`` via the mounted daemon socket,
     with a static Dockerfile validation fallback)
  3. Rotation interruption / recovery drill (crash after a committed
     re-wrap, restart, complete)
  4. Live archive API smoke test against the ``app`` compose service
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def step(title: str) -> None:
    print(f"\n=== {title} ===", flush=True)


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, cwd=REPO_ROOT, **kwargs)


def pytest_suite() -> None:
    step("1/4 code tests (pytest)")
    proc = run([sys.executable, "-m", "pytest", "-q", "tests"])
    if proc.returncode != 0:
        raise SystemExit(f"pytest failed with exit code {proc.returncode}")


def image_build_check() -> None:
    step("2/4 image build check")
    dockerfile = REPO_ROOT / "Dockerfile"
    text = dockerfile.read_text(encoding="utf-8")
    for needle in ("FROM python", "app.main"):
        if needle not in text:
            raise SystemExit(f"Dockerfile sanity check failed: missing {needle!r}")
    for referenced in ("app", "requirements.txt"):
        if not (REPO_ROOT / referenced).exists():
            raise SystemExit(f"Dockerfile references missing path: {referenced}")

    socket = os.environ.get("DOCKER_HOST") or "/var/run/docker.sock"
    socket_path = socket.removeprefix("unix://")
    if shutil.which("docker") and (
        socket_path.startswith("tcp:") or Path(socket_path).exists()
    ):
        image = os.environ.get("BUILD_IMAGE_TAG", "lx-archive:verify")
        proc = run(["docker", "build", "-t", image, "."])
        if proc.returncode != 0:
            raise SystemExit(f"docker build failed with exit code {proc.returncode}")
        print(f"[build] OK - built image {image}")
    else:
        print(
            "[build] docker daemon socket not available in this container; "
            "static Dockerfile validation passed (compose mounts "
            "/var/run/docker.sock for the full build check)"
        )


def crash_recovery_drill() -> None:
    step("3/4 rotation interruption and recovery drill")
    proc = run([sys.executable, "-m", "verify.e2e_crash"])
    if proc.returncode != 0:
        raise SystemExit(f"crash/recovery drill failed with exit code {proc.returncode}")


def api_smoke() -> None:
    step("4/4 archive API smoke test (against the app service)")
    base_url = os.environ.get("APP_BASE_URL", "http://app:8080")
    health_path = os.environ.get("HEALTH_PATH", "/healthz")
    proc = run(
        [sys.executable, "-m", "verify.smoke"],
        env={**os.environ, "APP_BASE_URL": base_url, "HEALTH_PATH": health_path},
    )
    if proc.returncode != 0:
        raise SystemExit(f"API smoke test failed with exit code {proc.returncode}")


def main() -> int:
    print("LXe archive verification: tests -> image build -> crash recovery -> API smoke")
    pytest_suite()
    image_build_check()
    crash_recovery_drill()
    api_smoke()
    print("\nALL VERIFICATION STEPS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
