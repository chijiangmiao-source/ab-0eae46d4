"""Runtime configuration, sourced entirely from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _int_env(name: str, default: int | None) -> int | None:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(f"invalid integer for {name}: {raw!r}") from exc


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    health_path: str
    db_path: str
    rotation_step_delay_ms: int
    rotation_crash_after: int | None
    rotation_crash_op: str | None

    @classmethod
    def from_env(cls) -> "Settings":
        health_path = os.environ.get("HEALTH_PATH", "/healthz")
        if not health_path.startswith("/"):
            health_path = "/" + health_path
        return cls(
            host=os.environ.get("APP_HOST", "0.0.0.0"),
            port=_int_env("APP_PORT", 8080) or 8080,
            health_path=health_path,
            db_path=os.environ.get("DB_PATH", "./archive.db"),
            rotation_step_delay_ms=_int_env("ROTATION_STEP_DELAY_MS", 0) or 0,
            rotation_crash_after=_int_env("ROTATION_CRASH_AFTER", None),
            rotation_crash_op=os.environ.get("ROTATION_CRASH_OP") or None,
        )
