"""Unit + crash-recovery tests for the archive store."""

from __future__ import annotations

import base64
import os

import pytest

from app.crypto import decrypt_record, unwrap_dek, wrap_dek, new_key
from app.store import ConflictError, NotFoundError, Store


@pytest.fixture()
def store(tmp_path):
    return Store(str(tmp_path / "archive.db"))


def _seal(store, n):
    texts = [f"calibration-set-{i}-v{i}" for i in range(n)]
    created = [store.create_record(t) for t in texts]
    return texts, created


def test_record_roundtrip_and_per_record_dek(store):
    a = store.create_record("LXe gain channel A: 1.024")
    b = store.create_record("LXe gain channel B: 0.987")
    assert a["kid"] == 1 and b["kid"] == 1
    assert a["wrap_version"] == "wrap:v1@k1"
    assert a["digest"] != b["digest"]
    # Independent data keys: wrapped blobs differ even before rotation.
    assert a["wrap_tag"] != b["wrap_tag"]
    records = store.list_records()
    assert [r["content"] for r in records] == [
        "LXe gain channel A: 1.024",
        "LXe gain channel B: 0.987",
    ]


def test_tampered_ciphertext_rejected(store):
    store.create_record("secret calibration")
    raw = store.debug_export()
    blob = bytearray(base64.b64decode(raw["records"][0]["ciphertext"]))
    blob[-1] ^= 0x01
    # Direct crypto check using the raw stored columns + active master key.
    import sqlite3

    conn = sqlite3.connect(store.db_path)
    row = conn.execute("SELECT * FROM records").fetchone()
    cols = [d[0] for d in conn.execute("SELECT * FROM records").description]
    data = dict(zip(cols, row))
    master = base64.b64decode(
        conn.execute("SELECT key_b64 FROM master_keys WHERE kid=1").fetchone()[0]
    )
    dek = unwrap_dek(data["wrapped_dek"], master, data["id"], data["kid"])
    tampered = base64.b64encode(bytes(blob)).decode()
    with pytest.raises(Exception):
        decrypt_record(tampered, dek, data["id"], data["digest"])


def test_wrap_aad_binds_record_and_kid(store):
    store.create_record("x")
    import sqlite3

    conn = sqlite3.connect(store.db_path)
    row = conn.execute("SELECT id, wrapped_dek, kid FROM records").fetchone()
    master = base64.b64decode(
        conn.execute("SELECT key_b64 FROM master_keys WHERE kid=1").fetchone()[0]
    )
    dek = unwrap_dek(row[1], master, row[0], row[2])
    # Same wrap cannot be interpreted under another record id.
    with pytest.raises(Exception):
        unwrap_dek(row[1], master, "R-9999", row[2])
    # Wrap freshly produced under k1 must not validate under a different kid AAD.
    wrap = wrap_dek(dek, master, row[0], 1)
    with pytest.raises(Exception):
        unwrap_dek(wrap, master, row[0], 2)
    assert unwrap_dek(wrap, master, row[0], 1) == dek


def test_rotation_rewraps_all_and_retires_old(store):
    texts, created = _seal(store, 4)
    before = store.debug_export()
    assert [r["kid"] for r in before["records"]] == [1] * 4

    state = store.start_or_replay_rotation("rot-A", None)
    assert state["state"] == "done"
    assert state["from_kid"] == 1 and state["to_kid"] == 2
    assert state["rewrapped"] == state["total"] == 4

    after = store.debug_export()
    # Ciphertext and digest bytes must be untouched; only the wrap changes.
    for b, a in zip(before["records"], after["records"]):
        assert b["ciphertext"] == a["ciphertext"]
        assert b["digest"] == a["digest"]
        assert b["wrapped_dek"] != a["wrapped_dek"]
        assert a["kid"] == 2

    # Key lifecycle: exactly one active, old key retired, new key active.
    states = {k["kid"]: k["state"] for k in after["keys"]}
    assert states == {1: "retired", 2: "active"}
    assert store.active_kid() == 2

    # Every archived reading remains readable with identical content/digest.
    read = store.list_records()
    assert [r["content"] for r in read] == texts
    assert [r["digest"] for r in read] == [r["digest"] for r in created]
    assert {r["wrap_version"] for r in read} == {"wrap:v1@k2"}


def test_idempotent_replay_same_params(store):
    _seal(store, 2)
    first = store.start_or_replay_rotation("rot-X", expected_kid=1)
    second = store.start_or_replay_rotation("rot-X", expected_kid=1)
    assert first["to_kid"] == second["to_kid"]
    assert second["state"] == "done"
    # Replay must not create another master key.
    kids = [k["kid"] for k in store.list_key_states()]
    assert kids == [1, 2]


def test_conflict_on_param_reuse_does_not_advance(store):
    _seal(store, 2)
    store.start_or_replay_rotation("rot-Y", expected_kid=1)
    with pytest.raises(ConflictError):
        store.start_or_replay_rotation("rot-Y", expected_kid=2)
    with pytest.raises(ConflictError):
        store.start_or_replay_rotation("rot-Y", None)
    # Nothing extra was staged by the rejected attempts.
    export = store.debug_export()
    assert sorted(k["kid"] for k in export["keys"]) == [1, 2]
    rot = store.get_rotation("rot-Y")
    assert rot["state"] == "done" and rot["rewrapped"] == 2


def test_expected_kid_mismatch_conflicts(store):
    _seal(store, 1)
    with pytest.raises(ConflictError):
        store.start_or_replay_rotation("rot-Z", expected_kid=99)
    assert store.active_kid() == 1
    with pytest.raises(NotFoundError):
        store.get_rotation("rot-Z")


def test_sealing_blocked_while_rotation_running(tmp_path):
    db = str(tmp_path / "blocked.db")
    store = Store(db)
    _seal(store, 3)
    # Arm a one-shot crash after the first rewrap to leave rotation running.
    store.arm_failpoint("rot-crash", after_commits=1)
    pid = os.fork()
    if pid == 0:
        try:
            Store(db).start_or_replay_rotation("rot-crash", None)
        except SystemExit:
            os._exit(77)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 77

    # While running, sealing is rejected and no half-rotated key is exposed.
    restarted = Store(db)
    assert restarted.list_running()[0]["op_id"] == "rot-crash"
    with pytest.raises(ConflictError):
        restarted.create_record("during rotation")
    assert len(restarted.list_records()) == 3


def test_interrupted_rotation_recovery_in_new_process(tmp_path):
    """Simulate real process death mid-rotation and restart from the same DB."""
    db = str(tmp_path / "archive.db")
    store = Store(db)
    texts, _ = _seal(store, 5)
    before = store.debug_export()

    store.arm_failpoint("rot-crash", after_commits=2)
    pid = os.fork()
    if pid == 0:
        # Child: fresh Store on same DB file, drives rotation and hard-exits.
        try:
            Store(db).start_or_replay_rotation("rot-crash", None)
        except SystemExit:
            os._exit(77)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 77

    # Restart: a brand-new Store sees an interrupted rotation with progress 2/5.
    restarted = Store(db)
    rot = restarted.get_rotation("rot-crash")
    assert rot["state"] == "running"
    assert rot["rewrapped"] == 2 and rot["total"] == 5

    # CRITICAL: all committed archives are still readable after the crash,
    # across both key versions (mixed half-rotated state).
    readable = restarted.list_records()
    assert sorted((r["id"], r["content"]) for r in readable) == sorted(
        (f"R-{i:04d}", t) for i, t in enumerate(texts, start=1)
    )
    kids = {r["id"]: r["kid"] for r in restarted.debug_export()["records"]}
    assert sorted(kids.values()) == [1, 1, 1, 2, 2]

    # Old master key is retained (not retired) mid-rotation.
    states = {k["kid"]: k["state"] for k in restarted.list_key_states()}
    assert states[1] in ("active",) and states[2] == "staged"

    # Ciphertext/digests of all rows unchanged by partial rotation.
    after_crash = restarted.debug_export()
    for b, a in zip(before["records"], after_crash["records"]):
        assert b["ciphertext"] == a["ciphertext"]
        assert b["digest"] == a["digest"]

    # Replay the SAME op_id to resume; completion activates k2/retires k1.
    final = restarted.start_or_replay_rotation("rot-crash", None)
    assert final["state"] == "done" and final["rewrapped"] == 5
    again = Store(db)
    assert again.list_records()
    states2 = {k["kid"]: k["state"] for k in again.list_key_states()}
    assert states2 == {1: "retired", 2: "active"}
    assert [r["content"] for r in again.list_records()] == texts


def test_resume_on_startup_completes(tmp_path):
    db = str(tmp_path / "rcv.db")
    s1 = Store(db)
    _seal(s1, 3)
    s1.arm_failpoint("rot-boot", after_commits=1)
    pid = os.fork()
    if pid == 0:
        try:
            Store(db).start_or_replay_rotation("rot-boot", None)
        except SystemExit:
            os._exit(77)
        os._exit(0)
    os.waitpid(pid, 0)

    s2 = Store(db)
    resumed = s2.resume_on_startup()
    assert resumed == ["rot-boot"]
    assert s2.get_rotation("rot-boot")["state"] == "done"
    assert s2.active_kid() == 2


def test_no_records_rotation_completes(store):
    state = store.start_or_replay_rotation("rot-empty", None)
    assert state["state"] == "done"
    assert state["total"] == 0 and state["rewrapped"] == 0
    assert store.active_kid() == 2


def test_new_records_after_rotation_use_new_key(store):
    _seal(store, 1)
    store.start_or_replay_rotation("rot-1", None)
    rec = store.create_record("post-rotation sealing")
    assert rec["kid"] == 2
    assert rec["wrap_version"] == "wrap:v1@k2"
