"""Archive API smoke test against the live `app` compose service."""
from __future__ import annotations

import time
import uuid

import httpx


def wait_for_health(client: httpx.Client, health_path: str, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            resp = client.get(health_path)
            if resp.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        if time.monotonic() > deadline:
            raise RuntimeError(f"service did not become healthy at {health_path}")
        time.sleep(0.5)


def wait_rotation_done(client: httpx.Client, operation_id: str, timeout: float = 90.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        status = client.get(f"/api/rotations/{operation_id}").json()
        if status["status"] == "completed":
            return status
        if time.monotonic() > deadline:
            raise RuntimeError(f"rotation {operation_id} did not finish: {status}")
        time.sleep(0.5)


def run(base_url: str, health_path: str) -> None:
    tag = uuid.uuid4().hex[:8]
    with httpx.Client(base_url=base_url, timeout=15.0) as client:
        wait_for_health(client, health_path)
        state0 = client.get("/api/state").json()
        v0 = state0["current_master_version"]
        assert isinstance(v0, int) and v0 >= 1, state0

        # Seal three records through the real API.
        ids = []
        for i in range(3):
            rid = f"smoke-{tag}-{i}"
            resp = client.post(
                "/api/records",
                json={
                    "record_id": rid,
                    "content": f"LXe 标定 smoke {tag} #{i}: 83mKr 41.5 keV 峰位 {510 + i} ADC",
                },
            )
            assert resp.status_code == 201, resp.text
            ids.append(rid)

        records = {r["id"]: r for r in client.get("/api/records").json()["records"]}
        for rid in ids:
            meta = records[rid]
            assert len(meta["digest"]) == 64, meta
            assert meta["wrap_version"] == v0, meta
            chk = client.post(f"/api/records/{rid}/verify").json()
            assert chk["ok"], chk

        # Start a rotation with a stable operation id.
        op = f"smoke-rot-{tag}"
        resp = client.post("/api/rotations", json={"operation_id": op})
        assert resp.status_code == 201, resp.text
        assert resp.json()["to_version"] == v0 + 1

        # Same operation retransmitted -> replay, no new state.
        replay = client.post("/api/rotations", json={"operation_id": op})
        assert replay.status_code == 200, replay.text
        assert replay.json()["operation_id"] == op
        assert replay.json()["to_version"] == v0 + 1

        # Same operation id with different parameters -> conflict.
        conflict = client.post(
            "/api/rotations", json={"operation_id": op, "target_version": v0 + 7}
        )
        assert conflict.status_code == 409, conflict.text

        final = wait_rotation_done(client, op)
        assert final["processed"] == final["total"], final

        state1 = client.get("/api/state").json()
        assert state1["current_master_version"] == v0 + 1, state1
        assert [k["version"] for k in state1["master_keys"]] == [v0 + 1], state1

        records2 = {r["id"]: r for r in client.get("/api/records").json()["records"]}
        for rid in ids:
            assert records2[rid]["wrap_version"] == v0 + 1, records2[rid]
            assert records2[rid]["digest"] == records[rid]["digest"]
            chk = client.post(f"/api/records/{rid}/verify").json()
            assert chk["ok"], chk

    print(f"[smoke] OK - 3 records sealed and re-wrapped, rotation {op} v{v0} -> v{v0 + 1}")


if __name__ == "__main__":
    import os

    run(
        os.environ.get("APP_BASE_URL", "http://app:8080"),
        os.environ.get("HEALTH_PATH", "/healthz"),
    )
