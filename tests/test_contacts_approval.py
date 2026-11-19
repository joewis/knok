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
