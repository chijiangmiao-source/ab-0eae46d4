"""End-to-end smoke test run inside the ``verify`` container.

It drives the *real* HTTP API of the archive service:

1. seals several calibration records and checks content digests and wrap versions;
2. arms a one-shot crash injection, then starts a rotation that hard-kills the
   archive process after 3 committed rewraps;
3. waits for the container/process to restart on its own, then asserts that
   every archived reading is still readable in the half-rotated state, that
   ciphertext/digests are byte-identical, and that the old key is retained;
4. replays the SAME op_id to resume and complete the rotation, then checks the
   new key activated and the old key retired;
5. proves same-op replay is idempotent while differing parameters conflict
   with 409 and advance nothing.

Exits non-zero on the first failed invariant.
"""

from __future__ import annotations

import hashlib
import os
import socket
import sys
import time

import requests

BASE = os.environ.get("SMOKE_BASE_URL", "http://archive:8080").rstrip("/")
HEALTH_PATH = os.environ.get("HEALTH_PATH", "/healthz")
OP_ID = os.environ.get("SMOKE_OP_ID", "smoke-rotation-1")
N_RECORDS = 5
CRASH_AFTER = 3

failures: list[str] = []


def check(cond: bool, message: str) -> None:
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {message}")
    if not cond:
        failures.append(message)


def wait_health(timeout: float = 60.0, expect_down: bool = False) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            r = requests.get(BASE + HEALTH_PATH, timeout=2)
            up = r.status_code == 200
            if expect_down and not up:
                return
            if not expect_down and up:
                return
            last = f"status={r.status_code}"
        except requests.RequestException as exc:
            last = type(exc).__name__
            if expect_down:
                return
        time.sleep(1)
    raise RuntimeError(f"health wait timed out (expect_down={expect_down}, last={last})")


def main() -> int:
    print(f"== smoke against {BASE} (health {HEALTH_PATH}) ==")

    wait_health()
    print("[1] page is served")
    page = requests.get(BASE + "/", timeout=5)
    check(page.status_code == 200, "console page HTTP 200")
    check("液氙".encode() in page.content, "console page renders archive UI")

    print("[2] sealing records through the real API")
    sealed = []
    for i in range(N_RECORDS):
        text = f"LXe-calibration channel {i} gain={1.0 + i / 1000:.4f}"
        r = requests.post(BASE + "/api/records", json={"text": text}, timeout=5)
        check(r.status_code == 201, f"seal record {i} -> 201")
        body = r.json()
        check(body["kid"] == 1, f"record {body['id']} wrapped under k1")
        check(body["wrap_version"] == "wrap:v1@k1", "wrap version reported")
        check(
            body["digest"] == hashlib.sha256(text.encode()).hexdigest(),
            "server digest matches sha256 of entered text",
        )
        sealed.append((body["id"], text, body["digest"]))

    before = requests.get(BASE + "/api/debug/state", timeout=5).json()
    check([r["kid"] for r in before["records"]] == [1] * N_RECORDS,
          "all records initially on k1")
    snapshot = {r["id"]: (r["ciphertext"], r["digest"]) for r in before["records"]}

    print("[3] arming crash after", CRASH_AFTER, "rewrap commits")
    r = requests.post(
        BASE + "/api/debug/failpoints",
        json={"op_id": OP_ID, "after_commits": CRASH_AFTER},
        timeout=5,
    )
    check(r.status_code == 200 and r.json()["armed"], "failpoint armed")

    print("[4] starting rotation; archive process must hard-crash")
    crashed = False
    try:
        requests.post(
            BASE + "/api/rotations", json={"op_id": OP_ID}, timeout=10
        )
    except requests.RequestException:
        crashed = True
    check(crashed, "connection dropped when the process crashed mid-rotation")

    print("[5] waiting for the process to restart and become healthy")
    wait_health(timeout=90)

    state = requests.get(BASE + f"/api/rotations/{OP_ID}", timeout=5).json()
    check(state["state"] == "running", "rotation is still 'running' after restart")
    check(state["rewrapped"] == CRASH_AFTER and state["total"] == N_RECORDS,
          f"progress persisted at {CRASH_AFTER}/{N_RECORDS} across the crash")

    dbg = requests.get(BASE + "/api/debug/state", timeout=5).json()
    kids = sorted(r["kid"] for r in dbg["records"])
    check(kids == [1] * (N_RECORDS - CRASH_AFTER) + [2] * CRASH_AFTER,
          "exactly the committed prefix moved to k2; tail still on k1")
    key_states = {k["kid"]: k["state"] for k in dbg["keys"]}
    check(key_states.get(1) == "active", "old master key still active mid-rotation")
    check(key_states.get(2) == "staged", "new master key only staged mid-rotation")

    print("[6] all committed archives remain readable after the crash")
    records = requests.get(BASE + "/api/records", timeout=5).json()
    by_id = {r["id"]: r for r in records}
    check(len(records) == N_RECORDS, "every record is listed")
    ok_cipher = ok_content = True
    for rec_id, text, digest in sealed:
        r = by_id[rec_id]
        if r["content"] != text or r["digest"] != digest:
            ok_content = False
        ct_now = next(x["ciphertext"] for x in dbg["records"] if x["id"] == rec_id)
        if ct_now != snapshot[rec_id][0] or r["digest"] != snapshot[rec_id][1]:
            ok_cipher = False
    check(ok_content, "all readings decrypt to exact original content+digest")
    check(ok_cipher, "ciphertext and digest bytes unchanged by partial rotation")

    print("[7] replaying the SAME op_id resumes and completes")
    r = requests.post(BASE + "/api/rotations", json={"op_id": OP_ID}, timeout=15)
    check(r.status_code == 200, "replay returns 200")
    final = r.json()
    check(final["state"] == "done", "rotation reached 'done'")
    check(final["rewrapped"] == N_RECORDS, "rewrapped counter at total")

    dbg2 = requests.get(BASE + "/api/debug/state", timeout=5).json()
    ks2 = {k["kid"]: k["state"] for k in dbg2["keys"]}
    check(ks2 == {1: "retired", 2: "active"},
          "only after full completion: k2 active, k1 retired")
    check(all(r["kid"] == 2 for r in dbg2["records"]), "all records now wrapped by k2")
    still_same = all(
        next(x for x in dbg2["records"] if x["id"] == rid)["ciphertext"] == ct
        and next(x for x in dbg2["records"] if x["id"] == rid)["digest"] == dg
        for rid, (ct, dg) in snapshot.items()
    )
    check(still_same, "ciphertext/digests still byte-identical after completion")
    records2 = requests.get(BASE + "/api/records", timeout=5).json()
    check({r["id"]: (r["content"], r["digest"]) for r in records2}
          == {rid: (text, dg) for rid, text, dg in sealed},
          "final reads match original calibration text exactly")

    print("[8] replay semantics")
    r1 = requests.post(BASE + "/api/rotations", json={"op_id": OP_ID}, timeout=5)
    check(r1.status_code == 200 and r1.json()["state"] == "done",
          "same op_id same params replays as no-op (200 done)")
    r2 = requests.post(
        BASE + "/api/rotations", json={"op_id": OP_ID, "expected_kid": 1}, timeout=5
    )
    check(r2.status_code == 409, "same op_id with differing params -> 409")
    overview = requests.get(BASE + "/api/rotations", timeout=5).json()
    check(overview["active_kid"] == 2, "conflicting retry did not roll key state back")

    print("[9] new records seal under the activated master key")
    r = requests.post(BASE + "/api/records", json={"text": "post-rotation"}, timeout=5)
    check(r.status_code == 201 and r.json()["kid"] == 2,
          "fresh record sealed directly under k2")

    if failures:
        print(f"\nSMOKE FAILED: {len(failures)} invariant(s) violated")
        for f in failures:
            print("  -", f)
        return 1
    print("\nSMOKE OK: crash-recovery rotation verified end to end")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # surface unexpected harness errors as failure
        print(f"SMOKE ERROR: {type(exc).__name__}: {exc}")
        sys.exit(2)
