from datetime import datetime, timedelta, timezone

import pytest

from knok.contacts import REQUEST_TTL, Contacts, ContactError, DuplicateRequest

T0 = datetime(2026, 11, 18, 5, 0, tzinfo=timezone.utc)
PEER = "muse@bridge.example"


@pytest.fixture
def contacts(tmp_path):
    with Contacts(tmp_path / "contacts.db") as store:
        yield store


def test_unknown_peer_is_none(contacts):
    assert contacts.state(PEER, T0) == "none"


def test_request_accept_flow(contacts):
    assert contacts.request(PEER, T0) == "requested"
    assert contacts.state(PEER, T0) == "requested"
    contacts.accept(PEER, T0)
    assert contacts.state(PEER, T0) == "accepted"
    assert contacts.accepted() == {PEER}


def test_duplicate_request_before_expiry_is_an_error(contacts):
    contacts.request(PEER, T0)
    with pytest.raises(DuplicateRequest):
        contacts.request(PEER, T0 + timedelta(hours=1))


def test_request_expires_after_seven_days(contacts):
    contacts.request(PEER, T0)
    assert contacts.state(PEER, T0 + REQUEST_TTL - timedelta(seconds=1)) == "requested"
    assert contacts.state(PEER, T0 + REQUEST_TTL) == "expired"


def test_expired_request_can_be_made_again(contacts):
    contacts.request(PEER, T0)
    assert contacts.state(PEER, T0 + REQUEST_TTL) == "expired"
    assert contacts.request(PEER, T0 + REQUEST_TTL + timedelta(seconds=1)) == "requested"


def test_accept_without_request_is_an_error(contacts):
    with pytest.raises(ContactError):
        contacts.accept(PEER, T0)


def test_refuse_removes_from_accepted(contacts):
    contacts.request(PEER, T0)
    contacts.accept(PEER, T0)
    contacts.refuse(PEER, T0)
    assert contacts.state(PEER, T0) == "refused"
    assert contacts.accepted() == set()


def test_state_survives_restart(tmp_path):
    path = tmp_path / "contacts.db"
    with Contacts(path) as store:
        store.request(PEER, T0)
        store.accept(PEER, T0)
    with Contacts(path) as store:
        assert store.state(PEER, T0) == "accepted"


def test_expire_marks_stale_requests(tmp_path):
    with Contacts(tmp_path / "c.db") as store:
        store.request(PEER, T0)
        assert store.expire(T0 + REQUEST_TTL) == 1
        assert store.state(PEER, T0 + REQUEST_TTL) == "expired"
