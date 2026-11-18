"""Phase 2 exit criterion: three agents on one host, isolated keys, offline delivery.

The demonstration in HUB.md, run against a real hub and real bridges over real HTTP:

    B is down. A sends. The hub holds the envelope. B starts, fetches, verifies, gates, fsyncs,
    acks. The hub deletes only after the ack.

Everything here runs in one process because the containers are the *deployment* of this, not a
different code path — `knok.runner` builds exactly these objects.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from knok.bridge import Bridge, BridgeState, load_cards
from knok.envelope import sign
from knok.hub import Hub
from knok.hubclient import HubClient
from knok.identity import Identity, b64url_decode, fingerprint
from knok.provision import load_key, provision

DOMAIN = "hub.local"
AGENTS = ["carl", "muse", "bobby"]


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def deployment(tmp_path: Path):
    """A provisioned root: hub key, three agent keys, one registry."""
    provision(tmp_path, hub_domain=DOMAIN, agents=AGENTS)
    # A private hub where every agent already knows every other: the gate's allow-list is the
    # pre-approval HUB.md describes, so a peer is admitted without a handshake round trip.
    for name in AGENTS:
        policy_path = tmp_path / "agents" / name / "policy.json"
        policy = json.loads(policy_path.read_text())
        policy["allow"] = [f"{other}@{DOMAIN}" for other in AGENTS if other != name]
        policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True))
    cards_dir = tmp_path / "registry"
    raw_cards = {p.stem: json.loads(p.read_text()) for p in cards_dir.glob("*.json")}
    registry = {}
    for agent_id, document in raw_cards.items():
        body = json.loads(b64url_decode(document["payload"]))
        key = body["bridge"]["publicKey"]
        registry[fingerprint(from_b64(key))] = key

    hub = Hub(
        path=tmp_path / "hub" / "hub.db",
        identity=load_key(f"postmaster@{DOMAIN}", tmp_path / "hub" / "identity.key"),
        cards=raw_cards,
        registry=registry,
        port=0,
        sweep_interval=3600,
    ).start()

    cards = load_cards(cards_dir)
    bridges = {}
    for name in AGENTS:
        agent_id = f"{name}@{DOMAIN}"
        state = BridgeState(
            agent_id=agent_id,
            directory=tmp_path / "agents" / name,
            hub_url=hub.url,
            registry=cards,
        )
        bridges[name] = Bridge(state, poll_seconds=0.01)
    yield hub, bridges, tmp_path
    for bridge in bridges.values():
        bridge.close()
    hub.stop()


def from_b64(public_b64: str):
    from knok.identity import public_key_from_b64

    return public_key_from_b64(public_b64)


def send(sender: Bridge, recipient_id: str, text: str, *, context=None, message_id=None):
    """Sign and deposit one message the way an agent's CLI does."""
    moment = now()
    unsigned = {
        "envelopeVersion": 1,
        "seq": 0,
        "message": {
            "kind": "message",
            "messageId": message_id or f"m-{moment.timestamp()}-{text[:4]}",
            "contextId": context or f"c-{moment.timestamp()}",
            "role": "agent",
            "parts": [{"kind": "text", "text": text}],
        },
        "from": sender.identity.agent_id,
        "to": [recipient_id],
        "sentAt": iso(moment - timedelta(seconds=1)),
        "expiresAt": iso(moment + timedelta(hours=72)),
        "turn": {"expectsReply": True, "closesThread": False},
    }
    envelope = sign(unsigned, sender.identity)
    client = HubClient(sender.state.hub_url, sender.identity)
    return client.deposit(envelope), envelope


def test_three_agents_have_isolated_keys(deployment):
    hub, bridges, root = deployment
    keys = {(root / "agents" / name / "identity.key").read_bytes() for name in AGENTS}
    assert len(keys) == 3, "agents must not share a key"
    ids = {bridges[name].identity.agent_id for name in AGENTS}
    assert len(ids) == 3

    # A key that is not the one the registry binds to this id must be refused at load, not
    # silently used to sign as Carl.
    from knok.bridge import fingerprint_key
    from knok.identity import IdentityError, load as load_bound

    carl_card = load_cards(root / "registry")[f"carl@{DOMAIN}"]
    expected = fingerprint_key(carl_card["bridge"]["publicKey"])
    with pytest.raises(IdentityError):
        load_bound(f"carl@{DOMAIN}", root / "agents" / "muse" / "identity.key", expected)


def test_offline_recipient_receives_on_return(deployment):
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

    # Muse is down: nothing polls for it.
    accepted, envelope = send(carl, muse.identity.agent_id, "Review this before I merge")
    message_id = envelope["message"]["messageId"]
    assert accepted["accepted"] is True

    # The hub holds it: carl's own poll sees nothing, muse's mailbox still has the message.
    carl.poll_once()
    assert muse.queue.get() is None, "nothing may reach the application before the bridge polls"

    # Muse returns.
    counts = muse.poll_once()
    assert counts["fetched"] == 1 and counts["queued"] == 1

    delivered = muse.queue.get()
    assert delivered is not None
    assert delivered["message"]["messageId"] == message_id
    assert delivered["message"]["parts"][0]["text"] == "Review this before I merge"

    # The hub deletes only after the ack: its mailbox is empty now, and a second poll delivers
    # nothing more.
    assert muse.client.fetch()["messages"] == [], "the acked message must be gone from the hub"
    second = muse.poll_once()
    assert second["queued"] == 0, "no duplicate may reach the application"


def test_kill_between_fetch_and_ack_redelivers_without_duplicating(deployment):
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    accepted, envelope = send(carl, muse.identity.agent_id, "one delivery only")
    message_id = envelope["message"]["messageId"]

    # Fetch, then die before acking: the wire call succeeded, the ack never happened.
    page = muse.client.fetch()
    assert [item["message"]["messageId"] for item in page["messages"]] == [message_id]

    # Restarted, Muse polls again and receives the same message; the queue dedupes it.
    first = muse.poll_once()
    assert first["queued"] == 1
    second_page = muse.client.fetch()
    assert second_page["messages"] == [], "the ack must have removed it from the hub"
    assert muse.queue.get() is not None
    assert muse.queue.get() is None, "the application sees exactly one copy"


def test_a_stranger_cannot_deposit(deployment, tmp_path):
    hub, bridges, root = deployment
    from knok.identity import generate

    stranger = generate("mallory", DOMAIN)
    client = HubClient(hub.url, stranger)
    moment = now()
    unsigned = {
        "envelopeVersion": 1,
        "seq": 0,
        "message": {
            "kind": "message",
            "messageId": "m-stranger",
            "contextId": "c-stranger",
            "role": "agent",
            "parts": [{"kind": "text", "text": "let me in"}],
        },
        "from": stranger.agent_id,
        "to": [bridges["muse"].identity.agent_id],
        "sentAt": iso(moment - timedelta(seconds=1)),
        "expiresAt": iso(moment + timedelta(hours=1)),
        "turn": {"expectsReply": False, "closesThread": False},
    }
    with pytest.raises(Exception) as refused:
        client.deposit(sign(unsigned, stranger))
    assert getattr(refused.value, "status", None) == 403

    counts = bridges["muse"].poll_once()
    assert counts["fetched"] == 0


def test_an_unverifiable_item_is_dropped_after_bounded_attempts(deployment):
    """Registry lag must not starve a mailbox forever.

    The hub knows bobby; this bridge's registry has not learned bobby's card yet. The message cannot
    be verified, so it must not be delivered — but after a bounded number of attempts it has to be
    acknowledged away, or it sits at the head of the mailbox and every message behind it waits
    forever.
    """
    from knok.bridge import MAX_HANDLE_ATTEMPTS
    from knok.hubclient import HubClient
    from knok.provision import load_key

    hub, bridges, root = deployment
    muse = bridges["muse"]

    bobby_identity = load_key(f"bobby@{DOMAIN}", root / "agents" / "bobby" / "identity.key")
    moment = now()
    unsigned = {
        "envelopeVersion": 1,
        "seq": 0,
        "message": {
            "kind": "message",
            "messageId": "m-unverifiable",
            "contextId": "c-blind",
            "role": "agent",
            "parts": [{"kind": "text", "text": "you cannot check my card yet"}],
        },
        "from": bobby_identity.agent_id,
        "to": [muse.identity.agent_id],
        "sentAt": iso(moment - timedelta(seconds=1)),
        "expiresAt": iso(moment + timedelta(hours=1)),
        "turn": {"expectsReply": False, "closesThread": False},
    }
    HubClient(hub.url, bobby_identity).deposit(sign(unsigned, bobby_identity))

    # The bridge has not learned bobby's card: this is registry lag, exactly what the bound is for.
    saved = muse.state.registry.pop(bobby_identity.agent_id)
    try:
        for _ in range(MAX_HANDLE_ATTEMPTS - 1):
            counts = muse.poll_once()
            assert counts["dropped"] == 0, "must not drop before the allowance is spent"
            assert counts["queued"] == 0, "an unverifiable message is never delivered"
            assert muse.client.fetch()["messages"], "still at the hub, still unacked"

        final = muse.poll_once()
        assert final["dropped"] == 1
        assert muse.client.fetch()["messages"] == [], "the drop must clear the mailbox"
        dropped = (root / "agents" / "muse" / "dropped.jsonl").read_text().splitlines()
        assert len(dropped) == 1 and "m-unverifiable" in dropped[0]
    finally:
        muse.state.registry[bobby_identity.agent_id] = saved


def test_reprovisioning_syncs_the_allow_list_for_a_new_agent(tmp_path):
    """An allow-list written once is a snapshot; adding an agent must update the others."""
    provision(tmp_path, hub_domain=DOMAIN, agents=["carl", "muse"])
    carl_policy = tmp_path / "agents" / "carl" / "policy.json"
    assert f"muse@{DOMAIN}" in json.loads(carl_policy.read_text())["allow"]

    provision(tmp_path, hub_domain=DOMAIN, agents=["carl", "muse", "bobby"])
    allow = json.loads(carl_policy.read_text())["allow"]
    assert f"bobby@{DOMAIN}" in allow, "a new agent must be admitted without hand-editing policies"


def test_a_drop_whose_record_cannot_be_written_is_not_acked(deployment, monkeypatch):
    """The record is the only evidence the message existed; without it, do not erase the original."""
    from knok.bridge import MAX_HANDLE_ATTEMPTS
    from knok.hubclient import HubClient
    from knok.provision import load_key

    hub, bridges, root = deployment
    muse = bridges["muse"]
    bobby_identity = load_key(f"bobby@{DOMAIN}", root / "agents" / "bobby" / "identity.key")

    moment = now()
    unsigned = {
        "envelopeVersion": 1,
        "seq": 0,
        "message": {
            "kind": "message",
            "messageId": "m-unrecordable",
            "contextId": "c-blind-2",
            "role": "agent",
            "parts": [{"kind": "text", "text": "drop me if you can"}],
        },
        "from": bobby_identity.agent_id,
        "to": [muse.identity.agent_id],
        "sentAt": iso(moment - timedelta(seconds=1)),
        "expiresAt": iso(moment + timedelta(hours=1)),
        "turn": {"expectsReply": False, "closesThread": False},
    }
    HubClient(hub.url, bobby_identity).deposit(sign(unsigned, bobby_identity))

    saved = muse.state.registry.pop(bobby_identity.agent_id)

    def refuse(path, *args, **kwargs):
        raise OSError("disk is read-only")

    try:
        for _ in range(MAX_HANDLE_ATTEMPTS - 1):
            counts = muse.poll_once()
            assert counts["queued"] == 0
        assert muse.client.fetch()["messages"], "four failures must not clear the mailbox"

        monkeypatch.setattr("builtins.open", refuse, raising=False)
        counts = muse.poll_once()
        monkeypatch.undo()
        assert counts["dropped"] == 0
        assert muse.client.fetch()["messages"], "a failed record must not clear the mailbox"

        # With the disk back, the next poll records the drop and clears it.
        counts = muse.poll_once()
        assert counts["dropped"] == 1
        assert muse.client.fetch()["messages"] == []
    finally:
        muse.state.registry[bobby_identity.agent_id] = saved


def test_a_late_notice_does_not_ack_away_the_message_it_names(tmp_path):
    """A late frame carries the id of a message still queued behind it (issue #19)."""
    from types import SimpleNamespace

    from knok.bridge import Bridge

    frame = {"kind": "late", "messageId": "m-1", "contextId": "c-1", "seq": 1}
    message = {
        "envelopeVersion": 1,
        "seq": 1,
        "message": {"kind": "message", "messageId": "m-1", "contextId": "c-1",
                    "role": "agent", "parts": [{"kind": "text", "text": "late"}]},
        "from": "carl@bridge.example",
        "to": ["muse@bridge.example"],
        "sentAt": "2026-11-18T05:00:00Z",
        "expiresAt": "2026-11-21T05:00:00Z",
        "turn": {"expectsReply": False, "closesThread": False},
    }

    class FakeQueue:
        def __init__(self):
            self.pending = [frame, message]
            self.acked: list[str] = []

        def get(self, now=None):
            return self.pending.pop(0) if self.pending else None

        def ack(self, message_id, now=None):
            self.acked.append(message_id)
            return True

    bridge = object.__new__(Bridge)
    bridge.state = SimpleNamespace(directory=tmp_path)
    bridge.queue = FakeQueue()

    # The inbox cannot be written: the message must survive, and nothing may be acked.
    (tmp_path / "inbox.jsonl").mkdir()

    assert bridge.drain() == 0
    assert bridge.queue.acked == [], "the late notice must not ack the message away"
    assert "m-1" in (tmp_path / "notices.jsonl").read_text()


def _drain_bridge(tmp_path, frames):
    from types import SimpleNamespace
    from knok.bridge import Bridge

    class FakeQueue:
        def __init__(self):
            self.pending = list(frames)
            self.confirmed: list[int] = []

        def get(self, now=None):
            return self.pending.pop(0) if self.pending else None

        def confirm_notice(self, notice_id, now=None):
            self.confirmed.append(notice_id)
            return True

    bridge = object.__new__(Bridge)
    bridge.state = SimpleNamespace(directory=tmp_path)
    bridge.queue = FakeQueue()
    return bridge


def test_a_notice_is_confirmed_only_after_it_is_on_disk(tmp_path):
    from knok.bridge import Bridge  # noqa: F401 - imported for the helper's use

    frame = {"kind": "dead", "messageId": "m-1", "contextId": "c-1",
             "attempts": 5, "deadedAt": "2026-11-18T05:00:00Z", "_noticeId": 9}
    bridge = _drain_bridge(tmp_path, [frame, None])
    assert bridge.drain() == 0
    assert bridge.queue.confirmed == [9]
    assert "deadedAt" in (tmp_path / "notices.jsonl").read_text()


def test_an_unwritable_notice_is_not_confirmed(tmp_path):
    """If the frame cannot be written, the queue must keep offering it."""
    frame = {"kind": "dead", "messageId": "m-1", "contextId": "c-1",
             "attempts": 5, "deadedAt": "2026-11-18T05:00:00Z", "_noticeId": 9}
    bridge = _drain_bridge(tmp_path, [frame, None])
    (tmp_path / "notices.jsonl").mkdir()  # every write raises
    assert bridge.drain() == 0
    assert bridge.queue.confirmed == []
