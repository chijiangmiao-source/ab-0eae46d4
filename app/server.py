"""Archive service entrypoint.

Environment:
  DB_PATH        SQLite file (default /data/archive.db)
  APP_PORT       listen port (default 8080)
  HEALTH_PATH    health endpoint path (default /healthz)
  RESUME_ON_BOOT 1 resumes interrupted rotations at startup (default 0:
                 recovery happens by replaying the same op_id)
"""

from __future__ import annotations

import os

from waitress import serve

from .store import Store
from .web import create_app


def main() -> None:
    db_path = os.environ.get("DB_PATH", "/data/archive.db")
    port = int(os.environ.get("APP_PORT", "8080"))
    resume = os.environ.get("RESUME_ON_BOOT", "0") == "1"

    store = Store(db_path)
    if resume:
        resumed = store.resume_on_startup()
        for op_id in resumed:
            print(f"[startup] resumed and completed interrupted rotation {op_id}")
    app = create_app(store)
    print(f"[archive] listening on 0.0.0.0:{port} (db={db_path})")
    serve(app, host="0.0.0.0", port=port, threads=8)


if __name__ == "__main__":
    main()
