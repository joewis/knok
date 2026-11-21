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

from knok.identity import IdentityError
from knok.queue import (BACKOFF_SECONDS, MAX_QUEUE_BYTES, MAX_QUEUE_MESSAGES,
                        NOTICE_BACKOFF_SECONDS, Queue, QueueFullError,
                        QueueLockedError)

T0 = datetime(2026, 11, 18, 5, 0, tzinfo=timezone.utc)
OWNER = "muse@bridge.example"  # the peer id the fixture envelopes are addressed to
SRC = Path(__file__).resolve().parents[2] / "src"


def _env(envelope_factory, **overrides):
    message = overrides.pop("message", {})
    env = envelope_factory()
    env["message"].update(message)
    # This module runs on a simulated clock pinned at T0, so the envelope has to
    # be dated against T0 as well — the shared fixture's wall-clock stamps would
    # otherwise sit in the future relative to every assertion here.
    env["sentAt"] = (T0 - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    env["expiresAt"] = (T0 + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    env.update(overrides)
    return env


def _at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


@pytest.fixture
def queue(tmp_path):
    q = Queue(tmp_path / "queue.sqlite", OWNER)
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
    with Queue(db, OWNER) as q:
        q.put(_env(envelope_factory, message={"messageId": "m-1"}), T0)
    with Queue(db, OWNER) as q:
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
    with Queue(tmp_path / "q.sqlite", OWNER, context_ttl=timedelta(seconds=60)) as q:
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
    with Queue(tmp_path / "q.sqlite", OWNER, context_ttl=timedelta(seconds=60)) as q:
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
    # Fifth backoff elapsed: dead, not re-offered — but the sender is told, once.
    frame = queue.get(now)
    assert frame["kind"] == "dead"
    assert frame["messageId"] == "m-1"
    assert frame["contextId"] == "c-1"
    assert frame["attempts"] == 5
    assert frame["deadedAt"]
    assert "message" not in frame  # a transport frame, not a Message
    assert queue.get(now) is None  # told once, not on every poll
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
    with Queue(db, OWNER) as q:
        q.put(_env(envelope_factory, message={"messageId": "m-1"}), T0)
        q.put(
            _env(envelope_factory, seq=1, message={"messageId": "m-2"}), T0
        )
        assert q.get(T0)["message"]["messageId"] == "m-1"
        q.ack("m-1")
    with Queue(db, OWNER) as q:
        assert q.get(T0)["message"]["messageId"] == "m-2"
        assert q.get(T0) is None


def _run_child(tmp_path, envelope, mode):
    db = tmp_path / "queue.sqlite"
    payload = tmp_path / "envelope.json"
    payload.write_text(json.dumps(envelope))
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "child_put.py"),
         str(db), str(payload), mode, T0.isoformat(), OWNER],
        env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 1, proc.stderr  # died by os._exit(1), as designed
    return db


def test_kill_before_ack_message_survives(tmp_path, envelope_factory):
    db = _run_child(tmp_path, _env(envelope_factory), "put")
    with Queue(db, OWNER) as q:
        # Real clock: crash recovery makes the message available at open time.
        got = q.get()
        assert got is not None and got["message"]["messageId"] == "m-1"


def test_kill_after_get_before_ack_replays(tmp_path, envelope_factory):
    db = _run_child(tmp_path, _env(envelope_factory), "put_get")
    with Queue(db, OWNER) as q:
        got = q.get()
        assert got is not None and got["message"]["messageId"] == "m-1"
        assert q.ack("m-1") is True
        assert q.get() is None


def test_durability_pragmas_in_effect(tmp_path):
    import sqlite3

    db = tmp_path / "queue.sqlite"
    with Queue(db, OWNER):
        pass
    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL
    finally:
        conn.close()


def test_second_opener_is_refused(tmp_path):
    q1 = Queue(tmp_path / "queue.sqlite", OWNER)
    try:
        with pytest.raises(QueueLockedError):
            Queue(tmp_path / "queue.sqlite", OWNER)
    finally:
        q1.close()
    # After close the lock is released and the queue opens again.
    with Queue(tmp_path / "queue.sqlite", OWNER):
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


def test_owner_id_validated_at_open(tmp_path):
    with pytest.raises(IdentityError, match="invalid agent id"):
        Queue(tmp_path / "queue.sqlite", "not-an-id")
    with pytest.raises(IdentityError, match="invalid agent id"):
        Queue(tmp_path / "queue.sqlite", "muse")
    # A well-formed id opens fine, even if it is not the fixture peer.
    with Queue(tmp_path / "queue.sqlite", "carl@bridge.example"):
        pass


def test_put_refuses_envelope_for_another_agent(queue, envelope_factory, identity):
    other = _env(envelope_factory, to=[identity.agent_id])  # carl, not muse
    with pytest.raises(
        ValueError, match="envelope is not addressed to muse@bridge.example"
    ):
        queue.put(other, T0)
    assert queue.get(T0) is None  # refused, not stored


def test_put_refuses_two_recipients(queue, envelope_factory, identity):
    both = _env(envelope_factory, to=[OWNER, identity.agent_id])
    with pytest.raises(
        ValueError, match="hub fan-out is not implemented: one queue serves one agent"
    ):
        queue.put(both, T0)
    assert queue.get(T0) is None  # refused, not silently keyed to the first


def test_get_returns_envelope_to_unchanged(queue, envelope_factory):
    assert queue.put(_env(envelope_factory), T0) == "accepted"
    got = queue.get(T0)
    assert got["to"] == [OWNER]  # get() never rewrites the recipient list
    assert got["from"] == "carl@bridge.example"


def test_late_arrival_after_release_is_delivered_with_a_late_notice(
    tmp_path, envelope_factory
):
    """The gap release skips a seq; the message bearing it must still arrive (issue #19)."""
    with Queue(tmp_path / "q.sqlite", OWNER, context_ttl=timedelta(seconds=60)) as q:
        for seq in (0, 2):
            q.put(
                _env(envelope_factory, seq=seq, message={"messageId": f"m-{seq}"}), T0
            )
        assert q.get(T0)["seq"] == 0
        q.ack("m-0", T0)
        gap = q.get(_at(61))
        assert gap["kind"] == "gap" and gap["missing"] == [1]
        assert q.get(_at(61))["seq"] == 2  # the held message, released in order

        # The skipped seq turns up after the release. Dropping it would destroy a
        # live message because a timer passed.
        assert q.put(
            _env(envelope_factory, seq=1, message={"messageId": "m-1"}), _at(62)
        ) == "late"

        late = q.get(_at(62))
        assert late["kind"] == "late"
        assert late["messageId"] == "m-1"
        assert late["seq"] == 1
        assert "message" not in late

        got = q.get(_at(62))
        assert got["seq"] == 1  # out of order, and delivered anyway
        assert got["message"]["messageId"] == "m-1"
        assert q.ack("m-1", _at(62)) is True
        assert q.get(_at(62)) is None


def test_a_late_arrival_is_not_reported_as_a_duplicate(queue, envelope_factory):
    """A delivered seq is still a duplicate; only a released gap makes an arrival late."""
    queue.put(_env(envelope_factory, seq=0, message={"messageId": "m-0"}), T0)
    assert queue.get(T0)["seq"] == 0
    queue.ack("m-0", T0)
    # Never skipped by a release: this is a re-send, not a late arrival.
    assert queue.put(
        _env(envelope_factory, seq=0, message={"messageId": "m-again"}), T0
    ) == "duplicate"
    assert queue.get(T0) is None


def test_seen_is_pruned_after_retention_and_live_messages_are_kept(
    tmp_path, envelope_factory
):
    """Dedupe memory must not grow forever, but must never forget a live message (issue #13)."""
    far = "2027-01-30T05:00:00Z"  # inside the 30-day bound used by the retention window
    with Queue(tmp_path / "q.sqlite", OWNER, context_ttl=timedelta(seconds=60)) as q:
        q.put(_env(envelope_factory, seq=0, message={"messageId": "m-gone"},
                   expiresAt=far), T0)
        q.ack("m-gone", T0)  # delivered: only ``seen`` remembers it now
        q.put(_env(envelope_factory, seq=1, message={"messageId": "m-live"},
                   expiresAt=far), T0)  # still live in the queue

        later = T0 + timedelta(days=31)
        assert q.expire(later) == []  # nothing expired; the prune runs anyway

        # The old id is forgotten, so a fresh message may reuse it...
        assert q.put(_env(envelope_factory, seq=5, message={"messageId": "m-gone"},
                          expiresAt=far), later) == "accepted"
        # ...while a live message's id is still defended, and re-putting it is a
        # clean duplicate rather than a primary-key collision.
        assert q.put(_env(envelope_factory, seq=6, message={"messageId": "m-live"},
                          expiresAt=far), later) == "duplicate"


def test_a_notice_is_re_offered_until_the_bridge_confirms_it(tmp_path, envelope_factory):
    """A notice marked delivered before it is written is lost with the process (review of #30)."""
    with Queue(tmp_path / "q.sqlite", OWNER) as q:
        q.put(_env(envelope_factory), T0)
        now = T0
        for attempt in range(5):
            q.get(now)
            now += timedelta(seconds=BACKOFF_SECONDS[attempt] + 1)

        first = q.get(now)
        assert first["kind"] == "dead"
        notice_id = first["_noticeId"]
        assert isinstance(notice_id, int)

        # Not re-offered inside the backoff: one drain loop must not spin on it.
        assert q.get(now) is None
        assert q.get(now + timedelta(seconds=59)) is None

        # The bridge crashed before writing it: it comes back, with the same id.
        second = q.get(now + timedelta(seconds=NOTICE_BACKOFF_SECONDS + 1))
        assert second["kind"] == "dead"
        assert second["_noticeId"] == notice_id

        assert q.confirm_notice(notice_id) is True
        assert q.get(now + timedelta(seconds=300)) is None  # confirmed: never again
        assert q.confirm_notice(notice_id) is False  # already delivered


def test_confirmed_notices_do_not_block_later_ones(tmp_path, envelope_factory):
    with Queue(tmp_path / "q.sqlite", OWNER, context_ttl=timedelta(seconds=60)) as q:
        for seq in (0, 2):
            q.put(_env(envelope_factory, seq=seq, message={"messageId": f"m-{seq}"}), T0)
        q.get(T0)
        q.ack("m-0", T0)
        gap = q.get(_at(61))
        assert gap["kind"] == "gap"
        assert q.confirm_notice(gap["_noticeId"]) is True
        assert q.get(_at(61))["seq"] == 2  # the released message follows the confirmed notice


def _late_notice(message_id: str, seq: int = 1) -> dict:
    return {
        "kind": "late",
        "messageId": message_id,
        "contextId": "c-1",
        "seq": seq,
        "from": "carl@bridge.example",
        "to": OWNER,
        "detectedAt": "2026-11-18T05:00:00Z",
    }


def test_a_notice_is_not_queued_twice_while_it_is_still_pending(queue):
    """One live notice per event: offering the same notice twice stores it once
    (issue #115). A delivered notice does not block a later one for the same event."""
    queue._queue_notice(_late_notice("m-1"), T0)
    queue._queue_notice(_late_notice("m-1"), T0)  # same event, offered twice

    first = queue.get(T0)
    assert first["kind"] == "late" and first["messageId"] == "m-1"
    # Taken, not confirmed: re-offered after the backoff, same id — not a twin.
    second = queue.get(T0 + timedelta(seconds=NOTICE_BACKOFF_SECONDS + 1))
    assert second["_noticeId"] == first["_noticeId"]
    assert queue.confirm_notice(first["_noticeId"]) is True
    # No twin left behind: the second offer was dropped, not stored.
    assert queue.get(T0 + timedelta(seconds=NOTICE_BACKOFF_SECONDS + 1)) is None

    # Delivered does not block: the same event may be noticed again later.
    queue._queue_notice(_late_notice("m-1"), T0)
    third = queue.get(T0)
    assert third["kind"] == "late" and third["_noticeId"] != first["_noticeId"]


def test_different_notices_are_each_queued(queue):
    """Dedupe is per event, not per kind: distinct notices all go out (issue #115)."""
    queue._queue_notice(_late_notice("m-1"), T0)
    queue._queue_notice(_late_notice("m-2", seq=2), T0)
    first = queue.get(T0)
    assert first["messageId"] == "m-1"
    assert queue.confirm_notice(first["_noticeId"]) is True
    second = queue.get(T0)
    assert second["messageId"] == "m-2"


def test_pending_notices_do_not_starve_due_messages(queue, envelope_factory):
    """A notice backlog delays a due message by at most one notice: notices and
    messages interleave instead of notices draining first (issue #115)."""
    queue.put(_env(envelope_factory, message={"messageId": "m-0"}), T0)
    for i in range(3):
        queue._queue_notice(_late_notice(f"n-{i}", seq=i), T0)

    first = queue.get(T0)
    assert first["kind"] == "late"  # the oldest notice still goes first
    got = queue.get(T0)
    assert got["message"]["messageId"] == "m-0"  # ...but the message is not starved
    assert queue.get(T0)["kind"] == "late"
    assert queue.get(T0)["kind"] == "late"
    assert queue.get(T0) is None


def test_the_local_cap_mirrors_the_hub_mailbox_cap():
    """The bound is HUB.md's, applied locally: 10,000 envelopes or 256 MiB per
    agent, whichever comes first (issue #116)."""
    assert MAX_QUEUE_MESSAGES == 10_000
    assert MAX_QUEUE_BYTES == 256 * 1024 * 1024


def test_put_refuses_when_the_message_cap_is_reached(tmp_path, envelope_factory):
    """At cap a new message is refused, not stored — the local queue cannot grow
    while the application is stalled (issue #116)."""
    with Queue(tmp_path / "q.sqlite", OWNER, max_messages=2) as q:
        assert q.put(
            _env(envelope_factory, seq=0, message={"messageId": "m-0"}), T0
        ) == "accepted"
        assert q.put(
            _env(envelope_factory, seq=1, message={"messageId": "m-1"}), T0
        ) == "accepted"
        with pytest.raises(QueueFullError):
            q.put(_env(envelope_factory, seq=2, message={"messageId": "m-2"}), T0)
        assert q.depth() == 2
        # A re-offer of an id already held is still a duplicate, not a refusal:
        # the bridge may ack it away.
        assert q.put(
            _env(envelope_factory, seq=0, message={"messageId": "m-0"}), T0
        ) == "duplicate"
        q.ack("m-0", T0)
        assert q.put(
            _env(envelope_factory, seq=2, message={"messageId": "m-2"}), T0
        ) == "accepted"


def test_put_refuses_when_the_byte_cap_is_reached(tmp_path, envelope_factory):
    """The byte half of the cap: one envelope fits, two do not (issue #116)."""
    with Queue(tmp_path / "probe.sqlite", OWNER) as probe:
        probe.put(_env(envelope_factory), T0)
        one = probe.usage()["bytes"]
    assert one > 0
    with Queue(tmp_path / "q.sqlite", OWNER, max_bytes=one) as q:
        assert q.put(
            _env(envelope_factory, message={"messageId": "m-0"}), T0
        ) == "accepted"
        with pytest.raises(QueueFullError):
            q.put(_env(envelope_factory, seq=1, message={"messageId": "m-1"}), T0)
    # Nothing at all fits in a one-byte queue.
    with Queue(tmp_path / "tiny.sqlite", OWNER, max_bytes=1) as q:
        with pytest.raises(QueueFullError):
            q.put(_env(envelope_factory), T0)


def test_usage_reports_count_and_bytes(queue, envelope_factory):
    """``usage`` is the cap's meter: live messages and the bytes they occupy."""
    first = _env(envelope_factory, seq=0, message={"messageId": "m-0"})
    second = _env(envelope_factory, seq=1, message={"messageId": "m-1"})
    queue.put(first, T0)
    queue.put(second, T0)
    expected = len(json.dumps(first, sort_keys=True).encode("utf-8")) + len(
        json.dumps(second, sort_keys=True).encode("utf-8")
    )
    assert queue.usage() == {"messages": 2, "bytes": expected}
    assert queue.depth() == 2
