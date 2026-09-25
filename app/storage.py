"""Durable, crash-safe persistence for the calibration archive.

Every multi-write mutation runs inside a single IMMEDIATE transaction, so the
persisted state is always one of:

* record sealed                -> one INSERT
* one record's DEK re-wrapped  -> UPDATE records + UPDATE rotation_items
                                  + UPDATE rotations (progress) in ONE txn
* rotation finalised           -> UPDATE rotations + UPDATE master_keys
                                  + UPDATE meta + DELETE old master in ONE txn

A crash between transactions merely leaves a ``running`` rotation behind,
which is resumed on the next boot.  SQLite runs in WAL mode with
``synchronous=FULL`` so committed transactions survive a power loss.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import threading
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS master_keys (
    version      INTEGER PRIMARY KEY,
    key_material BLOB NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('active', 'pending')),
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id           TEXT PRIMARY KEY,
    ciphertext   BLOB NOT NULL,
    digest       TEXT NOT NULL,
    aad          TEXT NOT NULL,
    dek_wrapped  BLOB NOT NULL,
    wrap_version INTEGER NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rotations (
    operation_id TEXT PRIMARY KEY,
    from_version INTEGER NOT NULL,
    to_version   INTEGER NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('running', 'completed')),
    total        INTEGER NOT NULL,
    processed    INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rotation_items (
    operation_id TEXT NOT NULL REFERENCES rotations(operation_id),
    record_id    TEXT NOT NULL REFERENCES records(id),
    status       TEXT NOT NULL CHECK (status IN ('pending', 'done')),
    PRIMARY KEY (operation_id, record_id)
);
"""

META_CURRENT_MASTER = "current_master_version"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Database:
    """Thread-safe SQLite store.  All public methods are serialised."""

    def __init__(self, path: str):
        self._lock = threading.RLock()
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=10000")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self._conn.execute(sql, params).fetchone()

    # ------------------------------------------------------------------
    # meta / master keys
    # ------------------------------------------------------------------
    def current_master(self) -> tuple[int, bytes] | None:
        """Return (version, key material) of the active master key."""
        with self._lock:
            row = self._one(
                "SELECT mk.version AS version, mk.key_material AS key_material "
                "FROM meta m JOIN master_keys mk "
                "  ON mk.version = CAST(m.value AS INTEGER) "
                "WHERE m.key = ?",
                (META_CURRENT_MASTER,),
            )
            if row is None:
                return None
            return int(row["version"]), bytes(row["key_material"])

    def provision_initial_master(self, key_material: bytes) -> int:
        """Create master key v1 if none exists; return the active version."""
        with self._lock:
            row = self._one("SELECT value FROM meta WHERE key = ?", (META_CURRENT_MASTER,))
            if row is not None:
                return int(row["value"])
            now = _utcnow()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._one("SELECT value FROM meta WHERE key = ?", (META_CURRENT_MASTER,))
                if row is not None:
                    self._conn.execute("COMMIT")
                    return int(row["value"])
                self._conn.execute(
                    "INSERT INTO master_keys(version, key_material, status, created_at) "
                    "VALUES (1, ?, 'active', ?)",
                    (key_material, now),
                )
                self._conn.execute(
                    "INSERT INTO meta(key, value) VALUES (?, '1')", (META_CURRENT_MASTER,)
                )
                self._conn.execute("COMMIT")
                return 1
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def master_key(self, version: int) -> bytes | None:
        with self._lock:
            row = self._one(
                "SELECT key_material FROM master_keys WHERE version = ?", (version,)
            )
            return bytes(row["key_material"]) if row else None

    def list_master_keys(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT version, status, created_at FROM master_keys ORDER BY version"
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # records
    # ------------------------------------------------------------------
    def create_record(self, record_id: str, build_fn) -> str:
        """Seal a record atomically.

        ``build_fn(master_version, master_key)`` is invoked *inside* the write
        transaction and must return ``(ciphertext, digest, aad, dek_wrapped)``.
        Reading the active master key inside the txn guarantees the record is
        either wrapped by the key that is current at commit time, or rejected
        because a rotation is running.

        Returns 'created' | 'exists' | 'rotation_active'.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if self._one("SELECT 1 AS x FROM rotations WHERE status = 'running'"):
                    self._conn.execute("ROLLBACK")
                    return "rotation_active"
                if self._one("SELECT 1 AS x FROM records WHERE id = ?", (record_id,)):
                    self._conn.execute("ROLLBACK")
                    return "exists"
                cur = self.current_master()
                if cur is None:
                    self._conn.execute("ROLLBACK")
                    raise RuntimeError("no active master key provisioned")
                version, key = cur
                ciphertext, digest, aad, dek_wrapped = build_fn(version, key)
                self._conn.execute(
                    "INSERT INTO records(id, ciphertext, digest, aad, dek_wrapped, "
                    "wrap_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (record_id, ciphertext, digest, aad, dek_wrapped, version, _utcnow()),
                )
                self._conn.execute("COMMIT")
                return "created"
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def get_record(self, record_id: str) -> dict | None:
        with self._lock:
            row = self._one("SELECT * FROM records WHERE id = ?", (record_id,))
            return dict(row) if row else None

    def list_records(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM records ORDER BY created_at, id"
            ).fetchall()
            return [dict(r) for r in rows]

    def count_records(self) -> int:
        with self._lock:
            return int(self._one("SELECT COUNT(*) AS n FROM records")["n"])

    # ------------------------------------------------------------------
    # rotations
    # ------------------------------------------------------------------
    def get_rotation(self, operation_id: str) -> dict | None:
        with self._lock:
            row = self._one("SELECT * FROM rotations WHERE operation_id = ?", (operation_id,))
            return dict(row) if row else None

    def running_rotation(self) -> dict | None:
        with self._lock:
            row = self._one("SELECT * FROM rotations WHERE status = 'running'")
            return dict(row) if row else None

    def list_rotations(self, status: str | None = None) -> list[dict]:
        with self._lock:
            if status is None:
                rows = self._conn.execute(
                    "SELECT * FROM rotations ORDER BY created_at, operation_id"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM rotations WHERE status = ? ORDER BY created_at, operation_id",
                    (status,),
                ).fetchall()
            return [dict(r) for r in rows]

    def rotation_items(self, operation_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT record_id, status FROM rotation_items "
                "WHERE operation_id = ? ORDER BY rowid",
                (operation_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def rotation_status_for_records(self) -> dict[str, str]:
        """Map record_id -> rotation item status for the running rotation."""
        with self._lock:
            running = self._one(
                "SELECT operation_id FROM rotations WHERE status = 'running'"
            )
            if running is None:
                return {}
            rows = self._conn.execute(
                "SELECT record_id, status FROM rotation_items WHERE operation_id = ?",
                (running["operation_id"],),
            ).fetchall()
            return {r["record_id"]: r["status"] for r in rows}

    def begin_rotation(
        self, operation_id: str, to_version: int | None, new_key: bytes
    ) -> tuple[str, dict | None]:
        """Persist a new rotation atomically (new pending master + snapshot).

        ``to_version=None`` means "next version".  Returns (outcome, rotation)
        with outcome in {'created', 'replay', 'conflict'}.
        """
        with self._lock:
            now = _utcnow()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._one(
                    "SELECT * FROM rotations WHERE operation_id = ?", (operation_id,)
                )
                if existing is not None:
                    self._conn.execute("COMMIT")
                    outcome = (
                        "replay"
                        if to_version is None or int(existing["to_version"]) == to_version
                        else "conflict"
                    )
                    return outcome, dict(existing)
                running = self._one("SELECT * FROM rotations WHERE status = 'running'")
                if running is not None:
                    self._conn.execute("COMMIT")
                    return "conflict", dict(running)
                cur = self.current_master()
                if cur is None:
                    self._conn.execute("ROLLBACK")
                    raise RuntimeError("no active master key provisioned")
                from_version = cur[0]
                target = to_version if to_version is not None else from_version + 1
                if target <= from_version or self.master_key(target) is not None:
                    self._conn.execute("ROLLBACK")
                    return "conflict", None
                ids = [
                    r["id"]
                    for r in self._conn.execute(
                        "SELECT id FROM records ORDER BY created_at, id"
                    ).fetchall()
                ]
                self._conn.execute(
                    "INSERT INTO master_keys(version, key_material, status, created_at) "
                    "VALUES (?, ?, 'pending', ?)",
                    (target, new_key, now),
                )
                self._conn.execute(
                    "INSERT INTO rotations(operation_id, from_version, to_version, "
                    "status, total, processed, created_at, updated_at) "
                    "VALUES (?, ?, ?, 'running', ?, 0, ?, ?)",
                    (operation_id, from_version, target, len(ids), now, now),
                )
                self._conn.executemany(
                    "INSERT INTO rotation_items(operation_id, record_id, status) "
                    "VALUES (?, ?, 'pending')",
                    [(operation_id, rid) for rid in ids],
                )
                self._conn.execute("COMMIT")
                return "created", self.get_rotation(operation_id)
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def next_pending_item(self, operation_id: str) -> str | None:
        with self._lock:
            row = self._one(
                "SELECT record_id FROM rotation_items "
                "WHERE operation_id = ? AND status = 'pending' ORDER BY rowid LIMIT 1",
                (operation_id,),
            )
            return row["record_id"] if row else None

    def claim_and_rewrap(
        self, operation_id: str, record_id: str, new_wrapped: bytes, to_version: int
    ) -> str:
        """Atomically re-wrap one record's DEK and advance rotation progress.

        Returns 'done' | 'already' | 'missing'.
        """
        with self._lock:
            now = _utcnow()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                item = self._one(
                    "SELECT status FROM rotation_items "
                    "WHERE operation_id = ? AND record_id = ?",
                    (operation_id, record_id),
                )
                if item is None:
                    self._conn.execute("ROLLBACK")
                    return "missing"
                if item["status"] == "done":
                    self._conn.execute("ROLLBACK")
                    return "already"
                # Only the wrapped DEK and its wrap version change; the
                # ciphertext, digest and AAD columns are never touched.
                self._conn.execute(
                    "UPDATE records SET dek_wrapped = ?, wrap_version = ? WHERE id = ?",
                    (new_wrapped, to_version, record_id),
                )
                self._conn.execute(
                    "UPDATE rotation_items SET status = 'done' "
                    "WHERE operation_id = ? AND record_id = ?",
                    (operation_id, record_id),
                )
                self._conn.execute(
                    "UPDATE rotations SET processed = processed + 1, updated_at = ? "
                    "WHERE operation_id = ?",
                    (now, operation_id),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            processed = int(
                self._one(
                    "SELECT processed FROM rotations WHERE operation_id = ?",
                    (operation_id,),
                )["processed"]
            )
            self._maybe_crash(operation_id, processed)
            return "done"

    def finalize_rotation(self, operation_id: str) -> str:
        """Activate the new master key and retire the old one, atomically.

        Only runs once every snapshot item is done.  Returns
        'completed' | 'not_ready' | 'missing'.
        """
        with self._lock:
            now = _utcnow()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                rot = self._one(
                    "SELECT * FROM rotations WHERE operation_id = ?", (operation_id,)
                )
                if rot is None:
                    self._conn.execute("ROLLBACK")
                    return "missing"
                if rot["status"] == "completed":
                    self._conn.execute("ROLLBACK")
                    return "completed"
                pending = int(
                    self._one(
                        "SELECT COUNT(*) AS n FROM rotation_items "
                        "WHERE operation_id = ? AND status = 'pending'",
                        (operation_id,),
                    )["n"]
                )
                if pending > 0:
                    self._conn.execute("ROLLBACK")
                    return "not_ready"
                to_version = int(rot["to_version"])
                self._conn.execute(
                    "UPDATE rotations SET status = 'completed', updated_at = ? "
                    "WHERE operation_id = ?",
                    (now, operation_id),
                )
                self._conn.execute(
                    "UPDATE master_keys SET status = 'active' WHERE version = ?",
                    (to_version,),
                )
                self._conn.execute(
                    "UPDATE meta SET value = ? WHERE key = ?",
                    (str(to_version), META_CURRENT_MASTER),
                )
                # Retire every previous master key: only the new one survives.
                self._conn.execute(
                    "DELETE FROM master_keys WHERE version != ?", (to_version,)
                )
                self._conn.execute("COMMIT")
                return "completed"
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------
    # crash injection (test hook, enabled via environment)
    # ------------------------------------------------------------------
    @staticmethod
    def _maybe_crash(operation_id: str, processed: int) -> None:
        crash_after = os.environ.get("ROTATION_CRASH_AFTER")
        if not crash_after:
            return
        crash_op = os.environ.get("ROTATION_CRASH_OP")
        if crash_op and crash_op != operation_id:
            return
        try:
            threshold = int(crash_after)
        except ValueError:
            return
        if processed == threshold:
            sys.stderr.write(
                f"[crash-injection] rotation {operation_id}: committed "
                f"{processed} re-wrapped record(s), exiting now\n"
            )
            sys.stderr.flush()
            os._exit(137)
