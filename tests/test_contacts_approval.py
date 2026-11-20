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
        store.approve("muse@hub", decided_by="joerg", fingerprint="", now=T0)
        with pytest.raises(ContactError, match="already been approved"):
            store.approve("muse@hub", decided_by="joerg", fingerprint="", now=T0)


# -- #65 append-only decisions -------------------------------------------------


def test_a_decision_is_appended_so_the_presentation_survives(tmp_path):
    """The core of #65: a decision must not overwrite what the owner was shown.

    The old shape reused one row, so a rotation during a held request left a single row whose
    fingerprint read as though the owner had refused the key that asked. Append-only keeps both
    facts, and ``superseded_by`` says which presentation a decision belongs to.
    """
    with Contacts(tmp_path / "c.db") as store:
        store.request("rotator@hub", now=T0, fingerprint="SHA256:old")
        store.deny("rotator@hub", decided_by="joerg", fingerprint="SHA256:new", now=T0)
        rows = store.decision_history("rotator@hub")
        assert len(rows) == 1
        assert rows[0]["presented_fingerprint"] == "SHA256:old"
        assert rows[0]["decided_fingerprint"] == "SHA256:new"
        assert rows[0]["decision"] == "denied"
        # The presentation record is untouched: it still says what the request carried.
        assert store.decision("rotator@hub")["presented_fingerprint"] == "SHA256:old"


def test_an_approval_cannot_be_recorded_against_a_key_the_owner_never_saw(tmp_path):
    """approve() refuses a fingerprint that is not the request's — and requires one at all."""
    with Contacts(tmp_path / "c.db") as store:
        store.request("muse@hub", now=T0, fingerprint="SHA256:abc")
        with pytest.raises(ContactError, match="not the key on the request"):
            store.approve("muse@hub", decided_by="joerg", fingerprint="SHA256:other", now=T0)
        assert store.decision("muse@hub") is None
        assert store.local_state("muse@hub", T0) == "held"


def test_a_rotation_between_presentations_leaves_two_rows_one_superseded(tmp_path):
    """A refreshed request supersedes the earlier presentation rather than replacing it."""
    with Contacts(tmp_path / "c.db") as store:
        store.request("rotator@hub", now=T0, fingerprint="SHA256:first")
        store.deny("rotator@hub", decided_by="joerg", fingerprint="SHA256:first", now=T0)
        # A refusal is terminal; the peer comes back later with a new key.
        with pytest.raises(ContactError):
            store.request("rotator@hub", now=T0, fingerprint="SHA256:second")
        rows = store.decision_history("rotator@hub")
        assert [r["presented_fingerprint"] for r in rows] == ["SHA256:first"]


def test_the_decided_fingerprint_is_readable_after_a_restart(tmp_path):
    """The audit is on disk, not in memory: reopening the store must show the same decision."""
    path = tmp_path / "c.db"
    with Contacts(path) as store:
        store.request("muse@hub", now=T0, fingerprint="SHA256:abc")
        store.approve("muse@hub", decided_by="joerg", fingerprint="SHA256:abc", now=T0)
    with Contacts(path) as store:
        row = store.decision("muse@hub")
        assert row is not None
        assert row["decision"] == "approved"
        assert row["decided_fingerprint"] == "SHA256:abc"


def test_a_second_decision_supersedes_the_first_even_when_it_is_the_latest_row(tmp_path):
    """The supersede must not depend on another peer having a newer row.

    A peer that decides, is revoked, and decides again has its first row as the global maximum
    when the second decision is recorded. Superseding only rows older than that maximum leaves
    both rows current, so the audit cannot say which decision stands.
    """
    with Contacts(tmp_path / "c.db") as store:
        store.request("peer@hub", now=T0, fingerprint="SHA256:first")
        store.approve("peer@hub", decided_by="joerg", fingerprint="SHA256:first", now=T0)
        store.accept("peer@hub", T0)
        store.revoke("peer@hub", T0)
        store.request("peer@hub", now=T0, fingerprint="SHA256:second")
        store.deny("peer@hub", decided_by="joerg", fingerprint="SHA256:second", now=T0)
        rows = store.decision_history("peer@hub")
        assert len(rows) == 2
        assert [r["presented_fingerprint"] for r in rows] == ["SHA256:first", "SHA256:second"]
        assert rows[0]["superseded_by"] == rows[1]["id"]
        assert rows[1]["superseded_by"] is None
        assert store.decision("peer@hub")["id"] == rows[1]["id"]
