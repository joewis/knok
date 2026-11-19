from datetime import datetime, timedelta, timezone

import pytest

from knok.contacts import (
    COOLDOWN,
    MAX_REQUEST_CHARS,
    MAX_REQUESTS,
    REQUEST_TTL,
    Contacts,
    ContactError,
    Cooldown,
    DuplicateRequest,
)
from knok.rates import Rates

T0 = datetime(2026, 11, 18, 5, 0, tzinfo=timezone.utc)
PEER = "muse@bridge.example"


@pytest.fixture
def contacts(tmp_path):
    with Contacts(tmp_path / "contacts.db") as store:
        yield store


def test_unknown_peer_is_none(contacts):
    assert contacts.state(PEER, T0) == "none"


def test_request_accept_flow(contacts):
    assert contacts.request(PEER, "hello", T0) == "requested"
    contacts.approve(PEER, "owner", now=T0)
    contacts.accept(PEER, T0)
    assert contacts.state(PEER, T0) == "accepted"
    assert contacts.accepted() == {PEER}


def test_duplicate_request_before_expiry_is_an_error(contacts):
    contacts.request(PEER, "hello", T0)
    with pytest.raises(DuplicateRequest):
        contacts.request(PEER, "hello again", T0 + timedelta(hours=1))


def test_request_expires_after_seven_days(contacts):
    contacts.request(PEER, "", T0)
    assert contacts.state(PEER, T0 + REQUEST_TTL - timedelta(seconds=1)) == "requested"
    assert contacts.state(PEER, T0 + REQUEST_TTL) == "expired"


def test_expired_request_can_be_made_again(contacts):
    contacts.request(PEER, "", T0)
    assert contacts.state(PEER, T0 + REQUEST_TTL) == "expired"
    assert contacts.request(PEER, "", T0 + REQUEST_TTL + timedelta(seconds=1)) == "requested"


def test_refusal_is_terminal(contacts):
    # SPEC §9's state diagram: refused -> requested is not an edge.
    contacts.request(PEER, "", T0)
    contacts.refuse(PEER, T0)
    with pytest.raises(ContactError, match="terminal"):
        contacts.request(PEER, "", T0 + timedelta(days=1))


def test_three_requests_then_a_cooldown(contacts):
    moment = T0
    for attempt in range(MAX_REQUESTS):
        contacts.request(PEER, f"attempt {attempt}", moment)
        moment += REQUEST_TTL + timedelta(seconds=1)
        assert contacts.state(PEER, moment) in {"expired", "requested"}
    with pytest.raises(Cooldown):
        contacts.request(PEER, "fourth", moment)
    # ...and it lifts after 30 days.
    assert contacts.request(PEER, "after cooldown", moment + COOLDOWN) == "requested"


def test_request_text_is_capped(contacts):
    with pytest.raises(ContactError, match="at most"):
        contacts.request(PEER, "x" * (MAX_REQUEST_CHARS + 1), T0)


def test_accept_without_request_is_an_error(contacts):
    with pytest.raises(ContactError):
        contacts.approve(PEER, "owner", now=T0)
        contacts.accept(PEER, T0)


def test_accepted_contact_is_withdrawn_by_revoke_not_refusal(contacts):
    # §9's diagram has no accepted -> refused edge; withdrawing an accepted contact is a local act.
    contacts.request(PEER, "", T0)
    contacts.approve(PEER, "owner", now=T0)
    contacts.accept(PEER, T0)
    contacts.revoke(PEER, T0)
    assert contacts.state(PEER, T0) == "none"
    assert contacts.accepted() == set()


def test_state_survives_restart(tmp_path):
    path = tmp_path / "contacts.db"
    with Contacts(path) as store:
        store.request(PEER, "", T0)
        store.approve(PEER, "owner", now=T0)
        store.accept(PEER, T0)
    with Contacts(path) as store:
        assert store.state(PEER, T0) == "accepted"


def test_expire_marks_stale_requests(tmp_path):
    with Contacts(tmp_path / "c.db") as store:
        store.request(PEER, "", T0)
        assert store.expire(T0 + REQUEST_TTL) == 1
        assert store.state(PEER, T0 + REQUEST_TTL) == "expired"


def test_cooldown_is_a_rolling_window_not_a_lifetime_quota(contacts):
    # Three requests spread over months must not throttle a peer forever: only attempts inside the
    # 30-day window count against it.
    contacts.request(PEER, "", T0)
    contacts.request(PEER, "", T0 + timedelta(days=40))
    contacts.request(PEER, "", T0 + timedelta(days=80))
    assert contacts.request(PEER, "", T0 + timedelta(days=88)) == "requested"


def test_refuse_requires_a_live_request(contacts):
    contacts.request(PEER, "", T0)
    contacts.approve(PEER, "owner", now=T0)
    contacts.accept(PEER, T0)
    with pytest.raises(ContactError, match="no live request"):
        contacts.refuse(PEER, T0)


def test_revoke_removes_an_accepted_contact(contacts):
    contacts.request(PEER, "", T0)
    contacts.approve(PEER, "owner", now=T0)
    contacts.accept(PEER, T0)
    contacts.revoke(PEER, T0)
    assert contacts.state(PEER, T0) == "none"
    assert contacts.accepted() == set()
    # ...and the peer may start again, unlike a refusal.
    assert contacts.request(PEER, "", T0) == "requested"


def test_daily_request_limit_is_enforced(tmp_path):
    rates = Rates(tmp_path / "rates.db")
    with Contacts(tmp_path / "c.db", rates=rates, contact_request_daily_limit=2) as store:
        store.request(PEER, "", T0)
        other = "bobby@bridge.example"
        store.request(other, "", T0)
        with pytest.raises(Cooldown, match="daily"):
            store.request("yiko@bridge.example", "", T0)
    rates.close()
