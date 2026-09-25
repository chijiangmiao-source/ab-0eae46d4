"""Archive service: sealing records and driving crash-safe key rotation."""
from __future__ import annotations

import threading
import time
from uuid import uuid4

from cryptography.exceptions import InvalidTag

from .crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    generate_key,
    record_aad,
    sha256_hex,
    wrap_aad,
)
from .storage import Database


class ConflictError(Exception):
    """Request conflicts with persisted state (HTTP 409)."""


class NotFoundError(Exception):
    """Requested entity does not exist (HTTP 404)."""


class ArchiveService:
    def __init__(self, db: Database, step_delay_ms: int = 0):
        self.db = db
        self.step_delay = step_delay_ms / 1000.0
        self._workers: dict[str, threading.Thread] = {}
        self._workers_lock = threading.Lock()
        self.db.provision_initial_master(generate_key())

    # ------------------------------------------------------------------
    # records
    # ------------------------------------------------------------------
    def create_record(self, content: str, record_id: str | None = None) -> dict:
        rid = record_id or uuid4().hex
        aad = record_aad(rid)
        plaintext = content.encode("utf-8")
        digest = sha256_hex(plaintext)

        def build_fn(master_version: int, master_key: bytes):
            dek = generate_key()
            ciphertext = aes_gcm_encrypt(dek, plaintext, aad.encode("utf-8"))
            dek_wrapped = aes_gcm_encrypt(master_key, dek, wrap_aad(rid))
            return ciphertext, digest, aad, dek_wrapped

        result = self.db.create_record(rid, build_fn)
        if result == "exists":
            raise ConflictError(f"record '{rid}' already exists")
        if result == "rotation_active":
            raise ConflictError(
                "master key rotation in progress; sealing is temporarily blocked"
            )
        return self.get_record(rid)

    def get_record(self, record_id: str) -> dict:
        rec = self.db.get_record(record_id)
        if rec is None:
            raise NotFoundError(f"record '{record_id}' not found")
        return self._record_dict(rec, self.db.rotation_status_for_records())

    def list_records(self) -> list[dict]:
        rotation_map = self.db.rotation_status_for_records()
        return [self._record_dict(r, rotation_map) for r in self.db.list_records()]

    def verify_record(self, record_id: str) -> dict:
        """Decrypt a record end-to-end and check digest + AAD integrity."""
        rec = self.db.get_record(record_id)
        if rec is None:
            raise NotFoundError(f"record '{record_id}' not found")
        key = self.db.master_key(int(rec["wrap_version"]))
        if key is None:
            return {
                "id": record_id,
                "ok": False,
                "error": f"master key v{rec['wrap_version']} is unavailable",
            }
        try:
            dek = aes_gcm_decrypt(key, bytes(rec["dek_wrapped"]), wrap_aad(record_id))
            plaintext = aes_gcm_decrypt(
                dek, bytes(rec["ciphertext"]), rec["aad"].encode("utf-8")
            )
        except InvalidTag:
            return {"id": record_id, "ok": False, "error": "GCM authentication failed"}
        digest_ok = sha256_hex(plaintext) == rec["digest"]
        aad_ok = rec["aad"] == record_aad(record_id)
        return {
            "id": record_id,
            "ok": digest_ok and aad_ok,
            "digest_ok": digest_ok,
            "aad_ok": aad_ok,
            "wrap_version": int(rec["wrap_version"]),
            "content_preview": plaintext.decode("utf-8", "replace")[:120],
        }

    # ------------------------------------------------------------------
    # rotations
    # ------------------------------------------------------------------
    def start_rotation(
        self, operation_id: str, target_version: int | None = None
    ) -> tuple[dict, bool]:
        """Start (or idempotently replay) a master-key rotation.

        Returns (rotation_status, created).  Replaying the same operation with
        the same parameters returns the persisted state; reusing the operation
        id with different parameters raises ConflictError without advancing
        any state.
        """
        existing = self.db.get_rotation(operation_id)
        if existing is not None:
            requested = (
                target_version if target_version is not None else existing["to_version"]
            )
            if int(requested) != int(existing["to_version"]):
                raise ConflictError(
                    f"operation '{operation_id}' already exists with "
                    f"target_version={existing['to_version']}"
                )
            if existing["status"] == "running":
                self._ensure_worker(operation_id)
            return self.rotation_status(operation_id), False

        outcome, _ = self.db.begin_rotation(operation_id, target_version, generate_key())
        if outcome == "conflict":
            raise ConflictError(
                "cannot start rotation: another rotation is running or the "
                "requested target_version is invalid"
            )
        if outcome == "created":
            self._ensure_worker(operation_id)
            return self.rotation_status(operation_id), True
        # Lost a race against a concurrent identical request: replay it.
        return self.rotation_status(operation_id), False

    def rotation_status(self, operation_id: str) -> dict:
        rot = self.db.get_rotation(operation_id)
        if rot is None:
            raise NotFoundError(f"rotation '{operation_id}' not found")
        return self._rotation_dict(rot)

    def list_rotations(self) -> list[dict]:
        return [self._rotation_dict(r) for r in self.db.list_rotations()]

    def resume_interrupted(self) -> list[str]:
        """Resume every rotation left 'running' by a previous process."""
        resumed = []
        for rot in self.db.list_rotations(status="running"):
            self._ensure_worker(rot["operation_id"])
            resumed.append(rot["operation_id"])
        return resumed

    def state(self) -> dict:
        running = self.db.running_rotation()
        completed = self.db.list_rotations(status="completed")
        current = self.db.current_master()
        return {
            "service": "lx-archive",
            "current_master_version": current[0] if current else None,
            "master_keys": self.db.list_master_keys(),
            "record_count": self.db.count_records(),
            "rotation": self._rotation_dict(running) if running else None,
            "last_rotation": self._rotation_dict(completed[-1]) if completed else None,
        }

    # ------------------------------------------------------------------
    # rotation worker
    # ------------------------------------------------------------------
    def _ensure_worker(self, operation_id: str) -> None:
        with self._workers_lock:
            worker = self._workers.get(operation_id)
            if worker is not None and worker.is_alive():
                return
            worker = threading.Thread(
                target=self._rotation_worker,
                args=(operation_id,),
                daemon=True,
                name=f"rotation-{operation_id}",
            )
            self._workers[operation_id] = worker
            worker.start()

    def _rotation_worker(self, operation_id: str) -> None:
        while True:
            rot = self.db.get_rotation(operation_id)
            if rot is None or rot["status"] != "running":
                return
            record_id = self.db.next_pending_item(operation_id)
            if record_id is None:
                # All records re-wrapped: only now may the new master key be
                # activated and the old one retired.
                self.db.finalize_rotation(operation_id)
                return
            self._rewrap_one(rot, record_id)

    def _rewrap_one(self, rot: dict, record_id: str) -> None:
        to_version = int(rot["to_version"])
        rec = self.db.get_record(record_id)
        if rec is None:
            # No delete API exists, but never wedge the rotation on a ghost.
            self.db.claim_and_rewrap(rot["operation_id"], record_id, b"", to_version)
            return
        if int(rec["wrap_version"]) == to_version:
            # Crash window: the row was already re-wrapped but the rotation
            # item was not marked done.  Keep the existing wrapped DEK.
            new_wrapped = bytes(rec["dek_wrapped"])
        else:
            from_key = self.db.master_key(int(rec["wrap_version"]))
            to_key = self.db.master_key(to_version)
            if from_key is None or to_key is None:
                raise RuntimeError("master key material missing during rotation")
            dek = aes_gcm_decrypt(from_key, bytes(rec["dek_wrapped"]), wrap_aad(record_id))
            new_wrapped = aes_gcm_encrypt(to_key, dek, wrap_aad(record_id))
        if self.step_delay > 0:
            time.sleep(self.step_delay)
        self.db.claim_and_rewrap(rot["operation_id"], record_id, new_wrapped, to_version)

    def wait_for_workers(self, timeout: float | None = None) -> bool:
        """Block until no rotation worker is alive (used by tests)."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._workers_lock:
                threads = [t for t in self._workers.values() if t.is_alive()]
            if not threads:
                return True
            for t in threads:
                remaining = None
                if deadline is not None:
                    remaining = max(0.0, deadline - time.monotonic())
                t.join(remaining)
            if deadline is not None and time.monotonic() >= deadline:
                with self._workers_lock:
                    return not any(t.is_alive() for t in self._workers.values())

    # ------------------------------------------------------------------
    # serialisation helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _record_dict(rec: dict, rotation_map: dict[str, str]) -> dict:
        return {
            "id": rec["id"],
            "digest": rec["digest"],
            "digest_preview": rec["digest"][:16],
            "wrap_version": int(rec["wrap_version"]),
            "aad": rec["aad"],
            "created_at": rec["created_at"],
            "rotation_status": rotation_map.get(rec["id"]),
        }

    def _rotation_dict(self, rot: dict) -> dict:
        items = self.db.rotation_items(rot["operation_id"])
        total = int(rot["total"])
        processed = int(rot["processed"])
        return {
            "operation_id": rot["operation_id"],
            "from_version": int(rot["from_version"]),
            "to_version": int(rot["to_version"]),
            "status": rot["status"],
            "total": total,
            "processed": processed,
            "percent": round(100.0 * processed / total, 1) if total else 100.0,
            "items": [
                {"record_id": i["record_id"], "status": i["status"]} for i in items
            ],
            "created_at": rot["created_at"],
            "updated_at": rot["updated_at"],
        }
