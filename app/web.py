"""HTTP layer: real JSON API plus the archivist's HTML console."""

from __future__ import annotations

import os
from typing import Any

from flask import Flask, jsonify, render_template, request

from .store import ConflictError, NotFoundError, Store


def create_app(store: Store) -> Flask:
    app = Flask(__name__)

    allow_failpoint = os.environ.get("ALLOW_FAILPOINT", "0") == "1"

    def error(status: int, message: str, **extra: Any):
        payload: dict[str, Any] = {"error": message}
        payload.update(extra)
        return jsonify(payload), status

    @app.errorhandler(ValueError)
    def _value_error(exc: ValueError):
        return error(400, str(exc))

    @app.errorhandler(ConflictError)
    def _conflict(exc: ConflictError):
        return error(409, str(exc))

    @app.errorhandler(NotFoundError)
    def _not_found(exc: NotFoundError):
        return error(404, str(exc))

    # ------------------------------------------------------------- console

    @app.get("/")
    def index():
        return render_template("index.html")

    # -------------------------------------------------------------- records

    @app.post("/api/records")
    def create_record():
        body = request.get_json(silent=True) or {}
        text = body.get("text")
        if not isinstance(text, str) or not text:
            raise ValueError("field 'text' must be a non-empty string")
        return jsonify(store.create_record(text)), 201

    @app.get("/api/records")
    def list_records():
        return jsonify(store.list_records())

    @app.get("/api/records/<rec_id>")
    def get_record(rec_id: str):
        return jsonify(store.get_record(rec_id))

    # ------------------------------------------------------------- rotation

    @app.post("/api/rotations")
    def start_rotation():
        body = request.get_json(silent=True) or {}
        op_id = body.get("op_id")
        if not isinstance(op_id, str) or not op_id.strip():
            raise ValueError("field 'op_id' must be a non-empty stable string")
        expected_kid = body.get("expected_kid")
        if expected_kid is not None:
            if isinstance(expected_kid, bool) or not isinstance(expected_kid, int):
                raise ValueError("field 'expected_kid' must be an integer or null")
        try:
            state = store.start_or_replay_rotation(op_id, expected_kid)
        except ConflictError as exc:
            # Reuse with differing parameters: surface current state untouched.
            current = None
            try:
                current = store.get_rotation(op_id)
            except NotFoundError:
                pass
            return error(409, str(exc), current=current)
        return jsonify(state), 200

    @app.get("/api/rotations/<op_id>")
    def get_rotation(op_id: str):
        return jsonify(store.get_rotation(op_id))

    @app.get("/api/rotations")
    def list_rotations():
        return jsonify(
            {
                "running": store.list_running(),
                "recent": store.list_rotations(),
                "keys": store.list_key_states(),
                "active_kid": store.active_kid(),
            }
        )

    # ----------------------------------------------------------- diagnostics

    @app.get("/api/debug/state")
    def debug_state():
        return jsonify(store.debug_export())

    @app.post("/api/debug/failpoints")
    def arm_failpoint():
        if not allow_failpoint:
            return error(403, "failpoints are disabled (set ALLOW_FAILPOINT=1)")
        body = request.get_json(silent=True) or {}
        op_id = body.get("op_id")
        after_commits = body.get("after_commits")
        if not isinstance(op_id, str) or not op_id.strip():
            raise ValueError("field 'op_id' is required")
        if not isinstance(after_commits, int) or isinstance(after_commits, bool):
            raise ValueError("field 'after_commits' must be a positive integer")
        store.arm_failpoint(op_id, after_commits)
        return jsonify({"armed": True, "op_id": op_id, "after_commits": after_commits})

    # ---------------------------------------------------------------- health

    health_path = os.environ.get("HEALTH_PATH", "/healthz")

    @app.get(health_path)
    def health():
        # Readiness means the database answers and a master key exists.
        store.active_kid()
        return jsonify({"status": "ok"}), 200

    return app
