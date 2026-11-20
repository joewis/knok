"""Every owner decision names the key that was on screen (#65).

A refusal used to record only the fingerprint from *presentation*. If the peer rotated their key
while the request sat held, the audit said "refused" against a fingerprint that no longer belonged
to anyone, so "the owner refused this key" and "the owner refused a key that had already rotated
away" were the same row. Kiko found this reading §9 against the code.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from knok.contacts import ContactError, Contacts

T0 = datetime(2026, 11, 18, 5, 0, tzinfo=timezone.utc)
PEER = "muse@bridge.example"


@pytest.fixture
def contacts(tmp_path):
    store = Contacts(tmp_path / "contacts.db")
    yield store
    store.close()


def held(store, fingerprint="SHA256:old"):
    store.request(PEER, "please add me", T0, fingerprint=fingerprint)


def test_an_approval_records_the_key_that_was_shown(contacts):
    held(contacts, "SHA256:old")
    contacts.approve(PEER, "owner", fingerprint="SHA256:old", now=T0)
    record = contacts.decision(PEER)
    assert record["decision"] == "approved"
    assert record["presented_fingerprint"] == "SHA256:old"
    assert record["decided_fingerprint"] == "SHA256:old"


def test_a_refusal_after_rotation_names_the_rotated_key(contacts):
    """The request was presented under the old key; the owner refused while looking at a new one."""
    held(contacts, "SHA256:old")
    contacts.deny(PEER, "owner", fingerprint="SHA256:new", now=T0)
    record = contacts.decision(PEER)
    assert record["decision"] == "denied"
    assert record["presented_fingerprint"] == "SHA256:old"
    assert record["decided_fingerprint"] == "SHA256:new"
    # The two are now distinguishable, which is the point of the column.
    assert record["presented_fingerprint"] != record["decided_fingerprint"]


def test_a_refusal_without_a_fingerprint_records_the_presented_one(contacts):
    held(contacts, "SHA256:old")
    contacts.deny(PEER, "owner", now=T0)
    assert contacts.decision(PEER)["decided_fingerprint"] == "SHA256:old"


def test_approving_a_different_key_is_still_refused(contacts):
    """The refusal side records a rotation; the approval side still refuses one, and must."""
    held(contacts, "SHA256:old")
    with pytest.raises(ContactError):
        contacts.approve(PEER, "owner", fingerprint="SHA256:new", now=T0)
    assert contacts.decision(PEER)["decision"] is None


def test_the_decided_fingerprint_survives_a_reopen(tmp_path):
    path = tmp_path / "contacts.db"
    store = Contacts(path)
    held(store, "SHA256:old")
    store.deny(PEER, "owner", fingerprint="SHA256:new", now=T0)
    store.close()

    reopened = Contacts(path)
    try:
        assert reopened.decision(PEER)["decided_fingerprint"] == "SHA256:new"
    finally:
        reopened.close()


def test_an_old_contacts_file_gains_the_column(tmp_path):
    """#65 must not require a fresh deployment: existing audit rows are migrated in place."""
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE approvals (peer TEXT PRIMARY KEY, text TEXT NOT NULL,"
        " fingerprint TEXT NOT NULL, presented TEXT NOT NULL, decision TEXT,"
        " decided_by TEXT, decided_at TEXT)"
    )
    conn.execute(
        "INSERT INTO approvals (peer, text, fingerprint, presented, decision)"
        " VALUES ('old@bridge.example', 'hi', 'SHA256:old', '2026-11-18T05:00:00Z', 'approved')"
    )
    conn.commit()
    conn.close()

    store = Contacts(path)
    try:
        assert store.decision("old@bridge.example")["decided_fingerprint"] is None
        assert store.decision("old@bridge.example")["decision"] == "approved"
    finally:
        store.close()
