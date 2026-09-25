"""HTTP API tests for the archive console."""

from __future__ import annotations

import pytest

from app.store import Store
from app.web import create_app


@pytest.fixture()
def client(tmp_path):
    app = create_app(Store(str(tmp_path / "web.db")))
    app.testing = True
    return app.test_client()


def _seal(client, text):
    return client.post("/api/records", json={"text": text})


def test_index_and_health(client):
    page = client.get("/")
    assert page.status_code == 200 and "液氙".encode() in page.data
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.get_json()["status"] == "ok"


def test_seal_and_list_via_api(client):
    r = _seal(client, "LXe-2026 calibration #1")
    assert r.status_code == 201
    body = r.get_json()
    assert body["id"] == "R-0001" and body["kid"] == 1
    assert len(body["digest"]) == 64
    assert body["content"] == "LXe-2026 calibration #1"

    listing = client.get("/api/records").get_json()
    assert len(listing) == 1 and listing[0]["wrap_version"] == "wrap:v1@k1"


def test_validation_errors(client):
    assert _seal(client, "").status_code == 400
    assert client.post("/api/records", json={}).status_code == 400
    assert (
        client.post("/api/rotations", json={"op_id": ""}).status_code == 400
    )
    assert (
        client.post("/api/rotations", json={"op_id": "x", "expected_kid": "1"})
        .status_code == 400
    )


def test_full_rotation_api_flow(client):
    for i in range(3):
        assert _seal(client, f"reading-{i}").status_code == 201

    r = client.post("/api/rotations", json={"op_id": "rot-api", "expected_kid": 1})
    assert r.status_code == 200
    state = r.get_json()
    assert state["state"] == "done" and state["rewrapped"] == 3

    overview = client.get("/api/rotations").get_json()
    assert overview["active_kid"] == 2
    assert {(k["kid"], k["state"]) for k in overview["keys"]} == {
        (1, "retired"),
        (2, "active"),
    }

    for rec in client.get("/api/records").get_json():
        assert rec["kid"] == 2
        assert rec["wrap_version"] == "wrap:v1@k2"
        assert rec["content"].startswith("reading-")


def test_replay_same_op_id_is_idempotent(client):
    _seal(client, "a")
    first = client.post("/api/rotations", json={"op_id": "dup", "expected_kid": 1})
    second = client.post("/api/rotations", json={"op_id": "dup", "expected_kid": 1})
    assert first.status_code == 200 and second.status_code == 200
    assert first.get_json()["to_kid"] == second.get_json()["to_kid"]


def test_param_reuse_conflicts_and_keeps_state(client):
    _seal(client, "a")
    ok = client.post("/api/rotations", json={"op_id": "op", "expected_kid": 1})
    assert ok.status_code == 200
    bad = client.post("/api/rotations", json={"op_id": "op", "expected_kid": 2})
    assert bad.status_code == 409
    body = bad.get_json()
    assert "different parameters" in body["error"]
    assert body["current"]["rewrapped"] == 1
    # Current state remains the completed rotation, untouched.
    got = client.get("/api/rotations/op").get_json()
    assert got["state"] == "done" and got["expected_kid"] == 1


def test_expected_kid_mismatch_is_409(client):
    _seal(client, "a")
    r = client.post("/api/rotations", json={"op_id": "m", "expected_kid": 42})
    assert r.status_code == 409


def test_failpoint_disabled_by_default(client):
    r = client.post(
        "/api/debug/failpoints", json={"op_id": "x", "after_commits": 1}
    )
    assert r.status_code == 403
