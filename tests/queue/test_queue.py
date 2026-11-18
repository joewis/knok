"""Slice 2 — durable queue (SPEC §6, issue #7).

Covers: fsync before ack (including a real kill/restart via a subprocess
that ``os._exit(1)``s), dedupe on ``messageId`` across restart, per-stream
``seq`` gap handling with ``resend`` and TTL release, dead-letter after
five attempts, expiry frames, and restart replay.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from knok.queue import BACKOFF_SECONDS, Queue, QueueLockedError

T0 = datetime(2026, 11, 18, 5, 0, tzinfo=timezone.utc)
SRC = Path(__file__).resolve().parents[2] / "src"


def _env(envelope_factory, **overrides):
    message = overrides.pop("message", {})
    env = envelope_factory()
    env["message"].update(message)
    env.update(overrides)
    return env


def _at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


@pytest.fixture
def queue(tmp_path):
    q = Queue(tmp_path / "queue.sqlite")
    yield q
    q.close()


def test_put_get_ack_roundtrip(queue, envelope_factory):
    assert queue.put(_env(envelope_factory), T0) == "accepted"
    got = queue.get(T0)
    assert got["message"]["messageId"] == "m-1"
    assert got["seq"] == 0
    assert queue.get(T0) is None  # handed out, awaiting ack — not re-offered
    assert queue.ack("m-1") is True
    assert queue.get(T0) is None
    assert queue.ack("m-1") is False  # already gone


def test_dedupe_on_message_id(queue, envelope_factory):
    assert queue.put(_env(envelope_factory, message={"messageId": "m-1"}), T0) == "accepted"
    # Same id, different seq and body: accepted and dropped, never twice.
    dup = _env(envelope_factory, seq=7, message={"messageId": "m-1"})
    dup["message"]["parts"] = [{"kind": "text", "text": "a different body"}]
    assert queue.put(dup, T0) == "duplicate"
    assert queue.get(T0)["seq"] == 0
    assert queue.get(T0) is None


def test_dedupe_survives_restart(tmp_path, envelope_factory):
    db = tmp_path / "queue.sqlite"
    with Queue(db) as q:
        q.put(_env(envelope_factory, message={"messageId": "m-1"}), T0)
    with Queue(db) as q:
        assert q.put(_env(envelope_factory, message={"messageId": "m-1"}), T0) == "duplicate"
        assert q.get(T0)["message"]["messageId"] == "m-1"
        assert q.get(T0) is None


def test_lower_seq_dropped_as_duplicate(queue, envelope_factory):
    for seq in (0, 1):
        queue.put(
            _env(envelope_factory, seq=seq, message={"messageId": f"m-{seq}"}), T0
        )
    queue.ack("m-0")
    queue.ack("m-1")
    # seq 0 is below the last delivered: dropped, not an error.
    assert queue.put(
        _env(envelope_factory, seq=0, message={"messageId": "m-late"}), T0
    ) == "duplicate"
    assert queue.get(T0) is None


def test_gap_holds_resend_reports_and_close_releases(queue, envelope_factory):
    for seq in (0, 1, 3):
        queue.put(
            _env(envelope_factory, seq=seq, message={"messageId": f"m-{seq}"}), T0
        )
    assert queue.get(T0)["seq"] == 0
    queue.ack("m-0")
    assert queue.get(T0)["seq"] == 1
    queue.ack("m-1")
    assert queue.get(T0) is None  # seq 3 held behind the gap at 2
    report = queue.resend("c-1", 2)
    assert report["missing"] == [2]
    assert report["nextExpected"] == 2
    assert report["available"] is False
    queue.put(_env(envelope_factory, seq=2, message={"messageId": "m-2"}), T0)
    assert queue.resend("c-1", 2)["missing"] == []
    assert queue.get(T0)["seq"] == 2
    queue.ack("m-2")
    assert queue.get(T0)["seq"] == 3  # held message released in order


def test_gap_released_in_order_with_notice_after_ttl(tmp_path, envelope_factory):
    with Queue(tmp_path / "q.sqlite", context_ttl=timedelta(seconds=60)) as q:
        for seq in (0, 2):
            q.put(
                _env(envelope_factory, seq=seq, message={"messageId": f"m-{seq}"}), T0
            )
        assert q.get(T0)["seq"] == 0
        q.ack("m-0", T0)
        assert q.get(_at(30)) is None  # inside the TTL: still held
        notice = q.get(_at(61))
        assert notice["kind"] == "gap"
        assert notice["contextId"] == "c-1"
        assert notice["missing"] == [1]
        assert "message" not in notice  # a transport frame, not a Message
        assert q.get(_at(61))["seq"] == 2
        q.ack("m-2")
        assert q.get(_at(61)) is None


def test_gap_closing_before_ttl_cancels_the_notice(tmp_path, envelope_factory):
    with Queue(tmp_path / "q.sqlite", context_ttl=timedelta(seconds=60)) as q:
        for seq in (0, 2):
            q.put(
                _env(envelope_factory, seq=seq, message={"messageId": f"m-{seq}"}), T0
            )
        assert q.get(T0)["seq"] == 0
        q.ack("m-0", T0)
        q.put(_env(envelope_factory, seq=1, message={"messageId": "m-1"}), _at(30))
        assert q.get(_at(61))["seq"] == 1  # no gap notice: the gap closed
        q.ack("m-1", _at(61))
        assert q.get(_at(61))["seq"] == 2


def test_backoff_between_attempts(queue, envelope_factory):
    queue.put(_env(envelope_factory), T0)
    assert queue.get(T0) is not None  # attempt 1
    assert queue.get(_at(BACKOFF_SECONDS[0] - 1)) is None
    assert queue.get(_at(BACKOFF_SECONDS[0] + 1)) is not None  # attempt 2
    assert queue.get(_at(BACKOFF_SECONDS[0] + BACKOFF_SECONDS[1] - 1)) is None


def test_dead_letter_after_five_attempts(queue, envelope_factory):
    queue.put(_env(envelope_factory), T0)
    # Walk the five attempts with their real backoffs: 1m, 5m, 30m, 2h, 12h.
    now = T0
    for attempt in range(5):
        assert queue.get(now) is not None, f"attempt {attempt + 1} not offered"
        now += timedelta(seconds=BACKOFF_SECONDS[attempt] + 1)
    assert queue.get(now) is None  # fifth backoff elapsed: dead, not re-offered
    dead = queue.dead_letter()
    assert len(dead) == 1
    assert dead[0]["messageId"] == "m-1"
    assert dead[0]["attempts"] == 5
    assert dead[0]["envelope"]["message"]["messageId"] == "m-1"
    assert queue.get(now) is None
    assert queue.dead_letter()[0]["messageId"] == "m-1"


def test_expire_emits_unsigned_frame(queue, envelope_factory):
    queue.put(
        _env(envelope_factory, message={"messageId": "m-soon"},
             expiresAt="2026-11-19T05:00:00Z"),
        T0,
    )
    queue.put(_env(envelope_factory, message={"messageId": "m-later"}), T0)
    frames = queue.expire(datetime(2026, 11, 19, 6, 0, tzinfo=timezone.utc))
    assert len(frames) == 1
    frame = frames[0]
    assert frame == {
        "kind": "expired",
        "messageId": "m-soon",
        "contextId": "c-1",
        "expiredAt": "2026-11-19T06:00:00Z",
    }
    assert "signature" not in frame and "message" not in frame
    assert queue.get(T0)["message"]["messageId"] == "m-later"
    # An expired id stays a duplicate: expiry must not resurrect it.
    assert queue.put(
        _env(envelope_factory, message={"messageId": "m-soon"},
             expiresAt="2026-11-19T05:00:00Z"),
        T0,
    ) == "duplicate"


def test_restart_replays_unacked_never_acked(tmp_path, envelope_factory):
    db = tmp_path / "queue.sqlite"
    with Queue(db) as q:
        q.put(_env(envelope_factory, message={"messageId": "m-1"}), T0)
        q.put(
            _env(envelope_factory, seq=1, message={"messageId": "m-2"}), T0
        )
        assert q.get(T0)["message"]["messageId"] == "m-1"
        q.ack("m-1")
    with Queue(db) as q:
        assert q.get(T0)["message"]["messageId"] == "m-2"
        assert q.get(T0) is None


def _run_child(tmp_path, envelope, mode):
    db = tmp_path / "queue.sqlite"
    payload = tmp_path / "envelope.json"
    payload.write_text(json.dumps(envelope))
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "child_put.py"),
         str(db), str(payload), mode, T0.isoformat()],
        env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 1, proc.stderr  # died by os._exit(1), as designed
    return db


def test_kill_before_ack_message_survives(tmp_path, envelope_factory):
    db = _run_child(tmp_path, _env(envelope_factory), "put")
    with Queue(db) as q:
        # Real clock: crash recovery makes the message available at open time.
        got = q.get()
        assert got is not None and got["message"]["messageId"] == "m-1"


def test_kill_after_get_before_ack_replays(tmp_path, envelope_factory):
    db = _run_child(tmp_path, _env(envelope_factory), "put_get")
    with Queue(db) as q:
        got = q.get()
        assert got is not None and got["message"]["messageId"] == "m-1"
        assert q.ack("m-1") is True
        assert q.get() is None


def test_durability_pragmas_in_effect(tmp_path):
    import sqlite3

    db = tmp_path / "queue.sqlite"
    with Queue(db):
        pass
    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL
    finally:
        conn.close()


def test_second_opener_is_refused(tmp_path):
    q1 = Queue(tmp_path / "queue.sqlite")
    try:
        with pytest.raises(QueueLockedError):
            Queue(tmp_path / "queue.sqlite")
    finally:
        q1.close()
    # After close the lock is released and the queue opens again.
    with Queue(tmp_path / "queue.sqlite"):
        pass


def test_sealed_envelope_refused(queue, envelope_factory):
    sealed = _env(envelope_factory)
    sealed["sealed"] = {"hpke": {"enc": "AA==", "ciphertext": "AA=="},
                        "recipientKeyId": "deadbeef"}
    del sealed["message"]
    with pytest.raises(ValueError, match="sealed"):
        queue.put(sealed, T0)


def test_expired_envelope_refused_at_put(queue, envelope_factory):
    with pytest.raises(ValueError, match="expired"):
        queue.put(_env(envelope_factory), datetime(2026, 11, 22, tzinfo=timezone.utc))
