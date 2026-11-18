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
