"""Service-level tests: sealing, rotation semantics, idempotency, recovery."""
import pytest

from app.crypto import aes_gcm_decrypt, aes_gcm_encrypt, generate_key, wrap_aad
from app.service import ArchiveService, ConflictError, NotFoundError
from app.storage import Database


@pytest.fixture(autouse=True)
def _no_crash_env(monkeypatch):
    for var in ("ROTATION_CRASH_AFTER", "ROTATION_CRASH_OP"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def service(tmp_path):
    db = Database(str(tmp_path / "archive.db"))
    svc = ArchiveService(db)
    yield svc
    db.close()


def make_records(svc, n):
    return [
        svc.create_record(f"LXe 标定 #{i}: 41.5 keV 峰位 {500 + i} ADC")["id"]
        for i in range(n)
    ]


def test_seal_and_verify(service):
    meta = service.create_record("LXe 标定: 83mKr 41.5 keV", record_id="rec-1")
    assert meta["id"] == "rec-1"
    assert meta["wrap_version"] == 1
    assert len(meta["digest"]) == 64
    chk = service.verify_record("rec-1")
    assert chk["ok"] and chk["digest_ok"] and chk["aad_ok"]
    assert "83mKr" in chk["content_preview"]


def test_duplicate_record_rejected(service):
    service.create_record("data", record_id="rec-1")
    with pytest.raises(ConflictError):
        service.create_record("other", record_id="rec-1")


def test_missing_record_404(service):
    with pytest.raises(NotFoundError):
        service.get_record("nope")
    with pytest.raises(NotFoundError):
        service.rotation_status("nope")


def test_rotation_rewraps_all_records(service):
    ids = make_records(service, 4)
    before = {rid: service.db.get_record(rid) for rid in ids}

    status, created = service.start_rotation("op-1")
    assert created and status["status"] == "running"
    assert status["total"] == 4
    assert service.wait_for_workers(10)

    final = service.rotation_status("op-1")
    assert final["status"] == "completed"
    assert final["processed"] == 4

    for rid in ids:
        after = service.db.get_record(rid)
        # Ciphertext, digest and AAD must be bit-identical after re-wrapping.
        assert after["ciphertext"] == before[rid]["ciphertext"]
        assert after["digest"] == before[rid]["digest"]
        assert after["aad"] == before[rid]["aad"]
        assert after["wrap_version"] == 2
        assert after["dek_wrapped"] != before[rid]["dek_wrapped"]
        assert service.verify_record(rid)["ok"]

    state = service.state()
    assert state["current_master_version"] == 2
    # Old master key retired: only the new one remains.
    assert [k["version"] for k in state["master_keys"]] == [2]


def test_rotation_replay_and_conflict(service):
    make_records(service, 2)
    s1, created1 = service.start_rotation("op-x")
    s2, created2 = service.start_rotation("op-x")
    assert created1 and not created2
    assert s1["operation_id"] == s2["operation_id"] == "op-x"
    assert s1["to_version"] == s2["to_version"]
    # Same operation id with different parameters must conflict and must not
    # advance any state.
    with pytest.raises(ConflictError):
        service.start_rotation("op-x", target_version=99)
    assert service.wait_for_workers(10)
    replay, created3 = service.start_rotation("op-x")
    assert not created3 and replay["status"] == "completed"
    with pytest.raises(ConflictError):
        service.start_rotation("op-x", target_version=99)


def test_second_rotation_blocked_while_running(tmp_path):
    db = Database(str(tmp_path / "a.db"))
    svc = ArchiveService(db, step_delay_ms=200)
    make_records(svc, 3)
    svc.start_rotation("op-a")
    with pytest.raises(ConflictError):
        svc.start_rotation("op-b")
    assert svc.wait_for_workers(10)
    db.close()


def test_creation_blocked_during_rotation(tmp_path):
    db = Database(str(tmp_path / "a.db"))
    svc = ArchiveService(db, step_delay_ms=200)
    make_records(svc, 3)
    svc.start_rotation("op-block")
    with pytest.raises(ConflictError):
        svc.create_record("must be rejected while rotation runs")
    assert svc.wait_for_workers(10)
    meta = svc.create_record("sealed after rotation")
    assert meta["wrap_version"] == 2
    db.close()


def test_rotation_with_zero_records(service):
    _, created = service.start_rotation("op-empty")
    assert created
    assert service.wait_for_workers(10)
    final = service.rotation_status("op-empty")
    assert final["status"] == "completed" and final["total"] == 0
    assert service.state()["current_master_version"] == 2


def test_chained_rotations(service):
    ids = make_records(service, 2)
    service.start_rotation("op-1")
    assert service.wait_for_workers(10)
    ids.append(service.create_record("post-rotation record")["id"])
    service.start_rotation("op-2")
    assert service.wait_for_workers(10)
    assert service.state()["current_master_version"] == 3
    for rid in ids:
        rec = service.get_record(rid)
        assert rec["wrap_version"] == 3
        assert service.verify_record(rid)["ok"]


def test_resume_interrupted_rotation(tmp_path):
    """Simulate a crash mid-rotation at the storage layer, then recover."""
    path = str(tmp_path / "a.db")
    db = Database(path)
    svc = ArchiveService(db)
    ids = make_records(svc, 3)
    before = {rid: db.get_record(rid) for rid in ids}

    new_key = generate_key()
    outcome, _ = db.begin_rotation("op-crash", None, new_key)
    assert outcome == "created"
    # Re-wrap exactly one record the way the worker would, then "crash".
    rid = db.next_pending_item("op-crash")
    rec = db.get_record(rid)
    dek = aes_gcm_decrypt(db.master_key(1), rec["dek_wrapped"], wrap_aad(rid))
    db.claim_and_rewrap("op-crash", rid, aes_gcm_encrypt(new_key, dek, wrap_aad(rid)), 2)
    db.close()

    # Restart on the same database file: the rotation must resume and finish.
    db2 = Database(path)
    svc2 = ArchiveService(db2)
    resumed = svc2.resume_interrupted()
    assert resumed == ["op-crash"]
    assert svc2.wait_for_workers(10)

    final = svc2.rotation_status("op-crash")
    assert final["status"] == "completed" and final["processed"] == 3
    for rid in ids:
        after = db2.get_record(rid)
        assert after["wrap_version"] == 2
        assert after["ciphertext"] == before[rid]["ciphertext"]
        assert after["digest"] == before[rid]["digest"]
        assert svc2.verify_record(rid)["ok"]
    assert svc2.state()["current_master_version"] == 2
    assert [k["version"] for k in svc2.state()["master_keys"]] == [2]
    db2.close()
