"""Rotation crash / recovery drill.

Spins up an isolated archive instance, injects a crash after the 2nd record
re-wrap (ROTATION_CRASH_AFTER=2 -> the process exits with code 137 right
after committing that record's transaction), inspects the persisted
mid-rotation state, then restarts the process on the same database and
verifies a complete, consistent recovery.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
CRASH_EXIT_CODE = 137


def read_db(path: str) -> dict:
    """Read raw persisted state straight from SQLite (no server involved)."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    try:
        records = {
            r["id"]: {
                "ciphertext": bytes(r["ciphertext"]),
                "digest": r["digest"],
                "aad": r["aad"],
                "dek_wrapped": bytes(r["dek_wrapped"]),
                "wrap_version": r["wrap_version"],
            }
            for r in conn.execute("SELECT * FROM records")
        }
        rotations = {
            r["operation_id"]: dict(r)
            for r in conn.execute("SELECT * FROM rotations")
        }
        items = [
            dict(r)
            for r in conn.execute(
                "SELECT operation_id, record_id, status FROM rotation_items"
            )
        ]
        keys = [
            (r["version"], r["status"])
            for r in conn.execute("SELECT version, status FROM master_keys ORDER BY version")
        ]
        meta = {r["key"]: r["value"] for r in conn.execute("SELECT * FROM meta")}
    finally:
        conn.close()
    return {
        "records": records,
        "rotations": rotations,
        "items": items,
        "master_keys": keys,
        "meta": meta,
    }


def wait_health(port: int, proc: subprocess.Popen, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/healthz"
    while True:
        if proc.poll() is not None:
            raise RuntimeError(f"server exited early with code {proc.returncode}")
        try:
            if httpx.get(url, timeout=2.0).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        if time.monotonic() > deadline:
            raise RuntimeError("server did not become healthy")
        time.sleep(0.4)


def start_server(env: dict, log_path: Path) -> subprocess.Popen:
    log = open(log_path, "ab")
    return subprocess.Popen(
        [sys.executable, "-m", "app.main"],
        cwd=REPO_ROOT,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )


def run() -> None:
    workdir = Path(os.environ.get("E2E_WORKDIR", "/tmp/lx-e2e"))
    port = int(os.environ.get("E2E_PORT", "18099"))
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)
    db_path = str(workdir / "archive.db")
    base_url = f"http://127.0.0.1:{port}"

    base_env = dict(os.environ)
    base_env.pop("ROTATION_CRASH_AFTER", None)
    base_env.pop("ROTATION_CRASH_OP", None)
    base_env.update(
        {
            "DB_PATH": db_path,
            "APP_PORT": str(port),
            "APP_HOST": "127.0.0.1",
            "HEALTH_PATH": "/healthz",
            "ROTATION_STEP_DELAY_MS": "60",
            "PYTHONUNBUFFERED": "1",
        }
    )

    # ---- phase 1: run with crash injection -------------------------------
    env1 = dict(base_env, ROTATION_CRASH_AFTER="2")
    proc1 = start_server(env1, workdir / "server-run1.log")
    op = f"e2e-rot-{uuid.uuid4().hex[:8]}"
    contents = {}
    try:
        wait_health(port, proc1)
        with httpx.Client(base_url=base_url, timeout=15.0) as client:
            for i in range(5):
                rid = f"e2e-{i}"
                content = f"LXe 标定 e2e #{i}: 83mKr 41.5 keV 峰位 {520 + i} ADC"
                resp = client.post(
                    "/api/records", json={"record_id": rid, "content": content}
                )
                assert resp.status_code == 201, resp.text
                contents[rid] = content

            resp = client.post("/api/rotations", json={"operation_id": op})
            assert resp.status_code == 201, resp.text
            assert resp.json()["total"] == 5

        raw_before = read_db(db_path)
        assert len(raw_before["records"]) == 5
        assert {r["wrap_version"] for r in raw_before["records"].values()} == {1}

        # The process must die by itself right after the 2nd committed re-wrap.
        rc = proc1.wait(timeout=60)
        assert rc == CRASH_EXIT_CODE, f"expected crash exit {CRASH_EXIT_CODE}, got {rc}"
    finally:
        if proc1.poll() is None:
            proc1.kill()
            proc1.wait()

    # ---- phase 2: inspect the persisted mid-rotation state ---------------
    mid = read_db(db_path)
    rot = mid["rotations"][op]
    assert rot["status"] == "running", rot
    assert rot["processed"] == 2, rot
    done = [i for i in mid["items"] if i["status"] == "done"]
    pending = [i for i in mid["items"] if i["status"] == "pending"]
    assert len(done) == 2 and len(pending) == 3, mid["items"]
    versions = {r["wrap_version"] for r in mid["records"].values()}
    assert versions == {1, 2}, versions
    # Both master keys must be retained; the old one is still active.
    assert sorted(v for v, _ in mid["master_keys"]) == [1, 2], mid["master_keys"]
    assert mid["meta"]["current_master_version"] == "1", mid["meta"]
    # Ciphertext, digest and AAD of every record are untouched so far.
    for rid, rec in mid["records"].items():
        assert rec["ciphertext"] == raw_before["records"][rid]["ciphertext"]
        assert rec["digest"] == raw_before["records"][rid]["digest"]
        assert rec["aad"] == raw_before["records"][rid]["aad"]

    # ---- phase 3: restart on the same database and recover ---------------
    proc2 = start_server(dict(base_env), workdir / "server-run2.log")
    try:
        wait_health(port, proc2)
        with httpx.Client(base_url=base_url, timeout=15.0) as client:
            deadline = time.monotonic() + 60
            while True:
                status = client.get(f"/api/rotations/{op}").json()
                if status["status"] == "completed":
                    break
                assert time.monotonic() < deadline, f"rotation stuck: {status}"
                time.sleep(0.5)
            assert status["processed"] == 5, status

            # Every committed archive stays readable after recovery.
            for rid, content in contents.items():
                chk = client.post(f"/api/records/{rid}/verify").json()
                assert chk["ok"], chk
                assert chk["wrap_version"] == 2, chk
                assert content[:60] in chk["content_preview"]

            state = client.get("/api/state").json()
            assert state["current_master_version"] == 2, state
            assert [k["version"] for k in state["master_keys"]] == [2], state

            # Retransmitting the finished operation replays it unchanged.
            replay = client.post("/api/rotations", json={"operation_id": op})
            assert replay.status_code == 200, replay.text
            assert replay.json()["status"] == "completed"
            assert replay.json()["processed"] == 5
            # Reusing the operation id with different parameters conflicts.
            conflict = client.post(
                "/api/rotations", json={"operation_id": op, "target_version": 3}
            )
            assert conflict.status_code == 409, conflict.text

        final = read_db(db_path)
        assert final["meta"]["current_master_version"] == "2", final["meta"]
        assert [v for v, _ in final["master_keys"]] == [2], final["master_keys"]
        for rid, rec in final["records"].items():
            assert rec["wrap_version"] == 2
            assert rec["ciphertext"] == raw_before["records"][rid]["ciphertext"]
            assert rec["digest"] == raw_before["records"][rid]["digest"]
            assert rec["aad"] == raw_before["records"][rid]["aad"]
            assert rec["dek_wrapped"] != raw_before["records"][rid]["dek_wrapped"]
    finally:
        proc2.terminate()
        try:
            proc2.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc2.kill()
            proc2.wait()

    print(f"[e2e] OK - crash after 2/5 re-wraps (exit {CRASH_EXIT_CODE}), "
          f"recovered and completed rotation {op} v1 -> v2")


if __name__ == "__main__":
    run()
