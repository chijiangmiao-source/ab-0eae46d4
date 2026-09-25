"""SQLite-backed persistence and the crash-safe rotation state machine.

Persistence model
------------------
* ``master_keys`` holds every master key material (base64) in one of the
  states ``active`` / ``staged`` / ``retired``.
* ``records`` stores the AES-256-GCM ciphertext, the plaintext digest, and the
  DEK wrapped under the master key version ``kid``.
* ``rotations`` is the idempotent, resumable rotation operation, keyed by a
  stable client-supplied ``op_id``.
* ``failpoints`` is an optional, explicitly enabled crash-injection hook used
  to prove recovery; its ``fired`` flag commits in the *same* transaction as
  the rewrap and progress update, so a crash can never desynchronise them.

Rotation safety properties
--------------------------
1. Each rewrap (new wrapped DEK + progress advance) is one durable
   transaction. Old master key material is retained for the whole rotation.
2. The new master key is only ``staged`` while rewrapping runs.
3. Activation of the new key and retirement of the old key happen in a single
   final transaction, and only after zero records remain wrapped by the old
   key and ``rewrapped == total``.
4. A crash at any point leaves either the old or the new wrap durably stored;
   on restart every record is decryptable because every referenced master key
   is retained. Replaying the same ``op_id`` (same parameters) resumes the
   rotation; reusing an ``op_id`` with different parameters fails with 409 and
   advances no state.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
import datetime as _dt
from typing import Any

from . import crypto

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS master_keys (
    kid        INTEGER PRIMARY KEY AUTOINCREMENT,
    key_b64    TEXT NOT NULL,
    state      TEXT NOT NULL CHECK (state IN ('active','staged','retired')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id          TEXT PRIMARY KEY,
    seq         INTEGER NOT NULL UNIQUE,
    ciphertext  TEXT NOT NULL,
    digest      TEXT NOT NULL,
    wrapped_dek TEXT NOT NULL,
    kid         INTEGER NOT NULL REFERENCES master_keys(kid),
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rotations (
    op_id         TEXT PRIMARY KEY,
    expected_kid  INTEGER,
    from_kid      INTEGER NOT NULL,
    to_kid        INTEGER NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('running','done')),
    total         INTEGER NOT NULL,
    rewrapped     INTEGER NOT NULL DEFAULT 0,
    started_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    completed_at  TEXT
);
CREATE TABLE IF NOT EXISTS failpoints (
    op_id        TEXT PRIMARY KEY,
    after_commits INTEGER NOT NULL,
    fired        INTEGER NOT NULL DEFAULT 0
);
"""


class ConflictError(Exception):
    """Request conflicts with rotation state; maps to HTTP 409."""


class NotFoundError(Exception):
    """Requested entity does not exist; maps to HTTP 404."""


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


class Store:
    """Thread-safe facade over a single SQLite database (WAL mode)."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        # Serialise writers; the rotation worker and request handlers may race.
        self._lock = threading.RLock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(SCHEMA)
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO schema_meta(key, value) VALUES ('schema_version', '1')"
                )
            # Bootstrap the first active master key on a fresh archive.
            active = conn.execute(
                "SELECT COUNT(*) AS n FROM master_keys WHERE state='active'"
            ).fetchone()
            if active["n"] == 0:
                exists = conn.execute("SELECT COUNT(*) AS n FROM master_keys").fetchone()
                if exists["n"] == 0:
                    conn.execute(
                        "INSERT INTO master_keys(key_b64, state, created_at) "
                        "VALUES (?, 'active', ?)",
                        (base64.b64encode(crypto.new_key()).decode("ascii"), _now()),
                    )

    # ------------------------------------------------------------------ keys

    def _key_row(self, conn: sqlite3.Connection, kid: int) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM master_keys WHERE kid=?", (kid,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"master key version {kid} is missing")
        return row

    def _key_material(self, conn: sqlite3.Connection, kid: int) -> bytes:
        return base64.b64decode(self._key_row(conn, kid)["key_b64"])

    def list_key_states(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT kid, state, created_at FROM master_keys ORDER BY kid"
            ).fetchall()
            return [dict(r) for r in rows]

    def active_kid(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT kid FROM master_keys WHERE state='active'"
            ).fetchone()
            if row is None:
                raise NotFoundError("no active master key")
            return int(row["kid"])

    # --------------------------------------------------------------- records

    def create_record(self, text: str) -> dict[str, Any]:
        """Seal a calibration text: generate a DEK, encrypt, wrap under active key."""
        if not isinstance(text, str) or not text:
            raise ValueError("text must be a non-empty string")
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            running = conn.execute(
                "SELECT op_id FROM rotations WHERE state='running'"
            ).fetchone()
            if running is not None:
                conn.execute("ROLLBACK")
                raise ConflictError(
                    f"rotation {running['op_id']} is in progress; sealing new records "
                    "is blocked until it completes"
                )
            seq = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM records"
            ).fetchone()["next_seq"]
            rec_id = f"R-{seq:04d}"
            active = conn.execute(
                "SELECT kid, key_b64 FROM master_keys WHERE state='active'"
            ).fetchone()
            kid = int(active["kid"])
            master = base64.b64decode(active["key_b64"])

            dek = crypto.new_key()
            ciphertext, digest = crypto.encrypt_record(text, dek, rec_id)
            wrapped = crypto.wrap_dek(dek, master, rec_id, kid)
            conn.execute(
                "INSERT INTO records(id, seq, ciphertext, digest, wrapped_dek, kid, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rec_id, seq, ciphertext, digest, wrapped, kid, _now()),
            )
            conn.execute("COMMIT")
        return self.get_record(rec_id)

    def _decrypt_row(self, conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        master = self._key_material(conn, row["kid"])
        dek = crypto.unwrap_dek(row["wrapped_dek"], master, row["id"], row["kid"])
        content = crypto.decrypt_record(row["ciphertext"], dek, row["id"], row["digest"])
        return {
            "id": row["id"],
            "digest": row["digest"],
            "kid": row["kid"],
            "wrap_version": f"wrap:{crypto.VERSION.decode()}@k{row['kid']}",
            "wrap_tag": row["wrapped_dek"][:16],
            "created_at": row["created_at"],
            "content": content,
        }

    def list_records(self) -> list[dict[str, Any]]:
        """Return every record with authenticated-decrypted content.

        Works in any rotation state: each record is unwrapped with the master
        key version recorded on the row, all of which are retained until a
        rotation fully completes.
        """
        out: list[dict[str, Any]] = []
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM records ORDER BY seq").fetchall()
            for row in rows:
                out.append(self._decrypt_row(conn, row))
        return out

    def get_record(self, rec_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM records WHERE id=?", (rec_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"record {rec_id} not found")
            return self._decrypt_row(conn, row)

    # -------------------------------------------------------------- rotation

    def get_rotation(self, op_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM rotations WHERE op_id=?", (op_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"rotation operation {op_id!r} not found")
            data = dict(row)
        data["active_kid"] = self.active_kid()
        return data

    def list_running(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM rotations WHERE state='running'"
            ).fetchall()
            return [dict(r) for r in rows]

    def list_rotations(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM rotations ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def start_or_replay_rotation(
        self, op_id: str, expected_kid: int | None
    ) -> dict[str, Any]:
        """Start a rotation for ``op_id`` or replay/resume an existing one.

        Same ``op_id`` + same parameters: replay (resumes if interrupted).
        Same ``op_id`` + different parameters: 409, no state change.
        """
        if not isinstance(op_id, str) or not op_id.strip():
            raise ValueError("op_id must be a non-empty string")
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM rotations WHERE op_id=?", (op_id,)
            ).fetchone()
            if existing is not None:
                stored_expected = existing["expected_kid"]
                if (stored_expected is None) != (expected_kid is None) or (
                    stored_expected is not None
                    and int(stored_expected) != int(expected_kid)
                ):
                    conn.execute("ROLLBACK")
                    raise ConflictError(
                        f"op_id {op_id!r} already exists with different parameters "
                        f"(stored expected_kid={stored_expected}, "
                        f"requested expected_kid={expected_kid}); state left untouched"
                    )
                # Idempotent replay: no mutation here; drive below if still running.
                conn.execute("ROLLBACK")
                return self.drive_rotation(op_id)

            other = conn.execute(
                "SELECT op_id FROM rotations WHERE state='running'"
            ).fetchone()
            if other is not None:
                conn.execute("ROLLBACK")
                raise ConflictError(
                    f"rotation {other['op_id']!r} is already in progress"
                )

            active = conn.execute(
                "SELECT kid, key_b64 FROM master_keys WHERE state='active'"
            ).fetchone()
            from_kid = int(active["kid"])
            if expected_kid is not None and int(expected_kid) != from_kid:
                conn.execute("ROLLBACK")
                raise ConflictError(
                    f"expected_kid={expected_kid} does not match active master key "
                    f"version {from_kid}"
                )
            total = conn.execute("SELECT COUNT(*) AS n FROM records").fetchone()["n"]

            cur = conn.execute(
                "INSERT INTO master_keys(key_b64, state, created_at) "
                "VALUES (?, 'staged', ?)",
                (base64.b64encode(crypto.new_key()).decode("ascii"), _now()),
            )
            to_kid = int(cur.lastrowid)
            conn.execute(
                "INSERT INTO rotations(op_id, expected_kid, from_kid, to_kid, state, "
                "total, rewrapped, started_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'running', ?, 0, ?, ?)",
                (op_id, expected_kid, from_kid, to_kid, total, _now(), _now()),
            )
            conn.execute("COMMIT")
        return self.drive_rotation(op_id)

    def drive_rotation(self, op_id: str) -> dict[str, Any]:
        """Perform resumable rewrapping, then atomically activate/retire keys.

        Safe to call repeatedly after crashes; records already on the new key
        are skipped, so committed work is never repeated or rolled back.
        """
        with self._lock:
            commits_this_run = 0
            while True:
                with self._connect() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    rot = conn.execute(
                        "SELECT * FROM rotations WHERE op_id=?", (op_id,)
                    ).fetchone()
                    if rot is None:
                        conn.execute("ROLLBACK")
                        raise NotFoundError(f"rotation {op_id!r} not found")
                    if rot["state"] == "done":
                        conn.execute("ROLLBACK")
                        return self.get_rotation(op_id)

                    rec = conn.execute(
                        "SELECT * FROM records WHERE kid=? ORDER BY seq LIMIT 1",
                        (rot["from_kid"],),
                    ).fetchone()
                    if rec is None:
                        self._finalize_rotation(conn, rot)
                        return self.get_rotation(op_id)

                    old_master = self._key_material(conn, rot["from_kid"])
                    new_master = self._key_material(conn, rot["to_kid"])
                    dek = crypto.unwrap_dek(
                        rec["wrapped_dek"], old_master, rec["id"], rot["from_kid"]
                    )
                    new_wrap = crypto.wrap_dek(
                        dek, new_master, rec["id"], rot["to_kid"]
                    )

                    fp = conn.execute(
                        "SELECT * FROM failpoints WHERE op_id=?", (op_id,)
                    ).fetchone()
                    will_fire = (
                        fp is not None
                        and not fp["fired"]
                        and commits_this_run + 1 == fp["after_commits"]
                    )
                    if will_fire:
                        # Marker commits in the SAME boundary as wrap + progress.
                        conn.execute(
                            "UPDATE failpoints SET fired=1 WHERE op_id=?", (op_id,)
                        )
                    cur = conn.execute(
                        "UPDATE records SET wrapped_dek=?, kid=? "
                        "WHERE id=? AND kid=?",
                        (new_wrap, rot["to_kid"], rec["id"], rot["from_kid"]),
                    )
                    if cur.rowcount != 1:
                        conn.execute("ROLLBACK")
                        raise RuntimeError("rewrap update affected unexpected rows")
                    conn.execute(
                        "UPDATE rotations SET rewrapped=rewrapped+1, updated_at=? "
                        "WHERE op_id=?",
                        (_now(), op_id),
                    )
                    conn.execute("COMMIT")

                commits_this_run += 1
                if will_fire:
                    # Simulate a hard process crash immediately after the
                    # durable rewrap+progress boundary has committed.
                    os._exit(77)

    def _finalize_rotation(self, conn: sqlite3.Connection, rot: sqlite3.Row) -> None:
        """Activation boundary: new key active, old key retired, rotation done.

        Runs entirely (including its checks) inside the caller's transaction.
        """
        remaining = conn.execute(
            "SELECT COUNT(*) AS n FROM records WHERE kid=?", (rot["from_kid"],)
        ).fetchone()["n"]
        on_target = conn.execute(
            "SELECT COUNT(*) AS n FROM records WHERE kid=?", (rot["to_kid"],)
        ).fetchone()["n"]
        if remaining != 0 or on_target != rot["total"] or rot["rewrapped"] != rot["total"]:
            conn.execute("ROLLBACK")
            raise RuntimeError(
                "refusing to activate new master key before every record is rewrapped "
                f"(remaining={remaining}, on_target={on_target}, "
                f"rewrapped={rot['rewrapped']}, total={rot['total']})"
            )
        conn.execute(
            "UPDATE master_keys SET state='retired' WHERE kid=? AND state='active'",
            (rot["from_kid"],),
        )
        conn.execute(
            "UPDATE master_keys SET state='active' WHERE kid=? AND state='staged'",
            (rot["to_kid"],),
        )
        # Belt-and-braces invariant: exactly one active key must result.
        n_active = conn.execute(
            "SELECT COUNT(*) AS n FROM master_keys WHERE state='active'"
        ).fetchone()["n"]
        if n_active != 1:
            conn.execute("ROLLBACK")
            raise RuntimeError(f"expected exactly one active key, found {n_active}")
        conn.execute(
            "UPDATE rotations SET state='done', completed_at=?, updated_at=? "
            "WHERE op_id=?",
            (_now(), _now(), rot["op_id"]),
        )
        conn.execute("DELETE FROM failpoints WHERE op_id=?", (rot["op_id"],))
        conn.execute("COMMIT")

    def resume_on_startup(self) -> list[str]:
        """Drive any rotation left 'running' by a previous process.

        Returns the op_ids that were resumed. Errors are swallowed per op so a
        problem never blocks the HTTP server from coming up healthy.
        """
        resumed: list[str] = []
        for rot in self.list_running():
            try:
                self.drive_rotation(rot["op_id"])
                resumed.append(rot["op_id"])
            except Exception as exc:  # pragma: no cover - defensive
                print(f"[startup] could not resume rotation {rot['op_id']}: {exc}")
        return resumed

    # ------------------------------------------------------------- failpoint

    def arm_failpoint(self, op_id: str, after_commits: int) -> None:
        """Persist a one-shot crash injection for a future rotation run."""
        if int(after_commits) < 1:
            raise ValueError("after_commits must be >= 1")
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO failpoints(op_id, after_commits, fired) VALUES (?, ?, 0) "
                "ON CONFLICT(op_id) DO UPDATE SET after_commits=excluded.after_commits, "
                "fired=0",
                (op_id, int(after_commits)),
            )

    def debug_export(self) -> dict[str, Any]:
        """Raw state for diagnostics (includes no key material)."""
        with self._connect() as conn:
            keys = [
                {"kid": r["kid"], "state": r["state"]}
                for r in conn.execute(
                    "SELECT kid, state FROM master_keys ORDER BY kid"
                ).fetchall()
            ]
            recs = [
                {
                    "id": r["id"],
                    "kid": r["kid"],
                    "digest": r["digest"],
                    "ciphertext": r["ciphertext"],
                    "wrapped_dek": r["wrapped_dek"],
                }
                for r in conn.execute(
                    "SELECT id, kid, digest, ciphertext, wrapped_dek FROM records ORDER BY seq"
                )
            ]
            rots = [
                dict(r)
                for r in conn.execute("SELECT * FROM rotations ORDER BY started_at")
            ]
            fps = [
                dict(r) for r in conn.execute("SELECT * FROM failpoints")
            ]
        return {"keys": keys, "records": recs, "rotations": rots, "failpoints": fps}
