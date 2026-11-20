"""Owner approval of contact requests (issue #42).

The rule these tests exist to hold down: **a request never becomes a contact without a recorded
owner decision.** It is a local precondition, not a wire state — the peer keeps seeing
``requested`` while the owner sees ``held`` — so the four-state wire machine is unchanged.
"""

from datetime import datetime, timedelta, timezone

import pytest

from knok.contacts import (MAX_PRESENTATIONS_PER_DAY, ContactError, Contacts,
                           DuplicateRequest)

T0 = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)


def test_a_request_is_held_locally_and_requested_on_the_wire(tmp_path):
    with Contacts(tmp_path / "c.db") as store:
        assert store.request("muse@hub", "hello", now=T0, fingerprint="SHA256:abc") == "requested"
        # The peer is told nothing new: the wire machine keeps its four states.
        assert store.state("muse@hub", T0) == "requested"
        # The owner sees the hold, with the text and the key that arrived.
        assert store.local_state("muse@hub", T0) == "held"
        assert store.pending() == [{"peer": "muse@hub", "at": T0.isoformat(),
                                    "text": "hello", "fingerprint": "SHA256:abc"}]


def test_accept_without_owner_approval_is_refused(tmp_path):
    """The invariant #42 names: no path may accept a request on its own."""
    with Contacts(tmp_path / "c.db") as store:
        store.request("muse@hub", now=T0, fingerprint="SHA256:abc")
        with pytest.raises(ContactError, match="not been approved"):
            store.accept("muse@hub", T0)


def test_approve_then_accept_makes_a_contact_and_records_who_decided(tmp_path):
    with Contacts(tmp_path / "c.db") as store:
        store.request("muse@hub", now=T0, fingerprint="SHA256:abc")
        store.approve("muse@hub", decided_by="joerg", fingerprint="SHA256:abc", now=T0)
        store.accept("muse@hub", now=T0)
        assert store.state("muse@hub", T0) == "accepted"
        assert store.pending() == []


def test_approval_carries_the_fingerprint_the_owner_was_shown(tmp_path):
    with Contacts(tmp_path / "c.db") as store:
        store.request("muse@hub", now=T0, fingerprint="SHA256:abc")
        with pytest.raises(ContactError, match="not the key on the request"):
            store.approve("muse@hub", decided_by="joerg", fingerprint="SHA256:different", now=T0)


def test_denial_is_terminal_and_a_later_request_is_refused(tmp_path):
    with Contacts(tmp_path / "c.db") as store:
        store.request("spammer@hub", now=T0)
        store.deny("spammer@hub", decided_by="joerg", now=T0)
        assert store.state("spammer@hub", T0) == "refused"
        with pytest.raises(ContactError, match="terminal"):
            store.request("spammer@hub", now=T0 + timedelta(days=1))


def test_a_held_request_expires_as_expired_never_accepted(tmp_path):
    with Contacts(tmp_path / "c.db") as store:
        store.request("muse@hub", now=T0)
        later = T0 + timedelta(days=8)
        assert store.state("muse@hub", later) == "expired"
        with pytest.raises(ContactError):
            store.accept("muse@hub", now=later)


def test_an_unanswered_request_is_not_presented_twice(tmp_path):
    with Contacts(tmp_path / "c.db") as store:
        store.request("muse@hub", now=T0)
        with pytest.raises(DuplicateRequest):
            store.request("muse@hub", now=T0 + timedelta(hours=1))
        assert len(store.pending()) == 1


def test_the_approval_queue_is_capped_per_day(tmp_path):
    """An uncapped queue makes the owner's prompt the spam channel (§9)."""
    with Contacts(tmp_path / "c.db") as store:
        for i in range(MAX_PRESENTATIONS_PER_DAY):
            store.request(f"peer{i}@hub", now=T0)
        with pytest.raises(ContactError, match="approval queue is full"):
            store.request("one-too-many@hub", now=T0)
        # The cap is a rolling day, not a lifetime quota.
        assert store.request("one-too-many@hub", now=T0 + timedelta(days=2)) == "requested"


def test_approve_twice_is_refused(tmp_path):
    with Contacts(tmp_path / "c.db") as store:
        store.request("muse@hub", now=T0)
        store.approve("muse@hub", decided_by="joerg", now=T0)
        with pytest.raises(ContactError, match="already been approved"):
            store.approve("muse@hub", decided_by="joerg", now=T0)


def test_an_approval_names_the_key_the_owner_saw(tmp_path):
    """#65: the audit answers "which key did the owner approve", not just "a request was held"."""
    with Contacts(tmp_path / "c.db") as store:
        store.request("muse@hub", now=T0, fingerprint="SHA256:abc")
        store.approve("muse@hub", decided_by="joerg", fingerprint="SHA256:abc", now=T0)
        row = store.decision("muse@hub")
        assert row is not None
        assert row["fingerprint"] == "SHA256:abc"
        assert row["decided_fingerprint"] == "SHA256:abc"
        assert row["decision"] == "approved"
        assert row["decided_by"] == "joerg"


def test_a_refusal_names_the_key_on_screen_not_the_one_that_rotated_away(tmp_path):
    """#65: a rotation while the request is held must not make two different facts one row.

    The request carried A. By the time the owner decides, the peer's key is B. Both are recorded:
    the presented fingerprint says what asked, the decided fingerprint says what was refused. The
    refusal is still terminal for the peer — the audit changes, not the wire.
    """
    with Contacts(tmp_path / "c.db") as store:
        store.request("rotator@hub", now=T0, fingerprint="SHA256:old")
        store.deny("rotator@hub", decided_by="joerg", fingerprint="SHA256:new", now=T0)
        row = store.decision("rotator@hub")
        assert row is not None
        assert row["fingerprint"] == "SHA256:old"
        assert row["decided_fingerprint"] == "SHA256:new"
        assert row["fingerprint"] != row["decided_fingerprint"]
        assert row["decision"] == "denied"
        assert store.state("rotator@hub", T0) == "refused"


def test_a_denial_without_a_named_key_records_the_presented_one(tmp_path):
    with Contacts(tmp_path / "c.db") as store:
        store.request("spammer@hub", now=T0, fingerprint="SHA256:abc")
        store.deny("spammer@hub", decided_by="joerg", now=T0)
        row = store.decision("spammer@hub")
        assert row is not None
        assert row["decided_fingerprint"] == row["fingerprint"] == "SHA256:abc"


def test_a_store_from_before_the_decision_fingerprint_still_decides(tmp_path):
    """The migration, not the fresh schema: an approvals table without the column is upgraded.

    A live bridge keeps its contacts.db across upgrades, so ``CREATE TABLE IF NOT EXISTS`` alone
    would leave every existing store unable to record a decision fingerprint.
    """
    import sqlite3

    path = tmp_path / "c.db"
    legacy = sqlite3.connect(str(path))
    legacy.execute(
        "CREATE TABLE contacts (peer TEXT PRIMARY KEY, state TEXT NOT NULL, updated TEXT NOT NULL,"
        " requests INTEGER NOT NULL DEFAULT 0, last_request TEXT)"
    )
    legacy.execute(
        "CREATE TABLE approvals (peer TEXT PRIMARY KEY, text TEXT NOT NULL,"
        " fingerprint TEXT NOT NULL, presented TEXT NOT NULL, decision TEXT,"
        " decided_by TEXT, decided_at TEXT)"
    )
    legacy.commit()
    legacy.close()

    with Contacts(path) as store:
        store.request("muse@hub", now=T0, fingerprint="SHA256:abc")
        store.deny("muse@hub", decided_by="joerg", fingerprint="SHA256:def", now=T0)
        row = store.decision("muse@hub")
        assert row is not None
        assert row["decided_fingerprint"] == "SHA256:def"
