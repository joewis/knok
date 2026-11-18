"""Shared scaffolding for the transport tests: a local pair of bridges.

Each bridge owns its own identity, queue, contacts, threads and gate, and
holds the *registered* cards of the agents it may hear from — the local-pair
stand-in for the hub registry (§4: no trust-on-first-use).
"""

from __future__ import annotations

import secrets
from types import SimpleNamespace

from knok.contacts import Contacts
from knok.envelope import sign
from knok.gate import Gate, Threads
from knok.identity import generate
from knok.policy import parse
from knok.queue import Queue
from knok.transport import Bridge, make_agent_card, registry_for

HUB = "bridge.example"
SENT_AT = "2026-11-18T05:00:00Z"
EXPIRES_AT = "2026-11-21T05:00:00Z"


def new_message_id() -> str:
    return "m-" + secrets.token_hex(16)  # 128 bits from a CSPRNG (§6)


def build_envelope(sender, recipient_id, *, seq=0, message_id=None,
                   context_id="c-1", text="Can you review §4?",
                   expects_reply=True, closes_thread=False):
    unsigned = {
        "envelopeVersion": 1,
        "seq": seq,
        "message": {
            "kind": "message",
            "messageId": message_id or new_message_id(),
            "contextId": context_id,
            "role": "agent",
            "parts": [{"kind": "text", "text": text}],
        },
        "from": sender.agent_id,
        "to": [recipient_id],
        "sentAt": SENT_AT,
        "expiresAt": EXPIRES_AT,
        "turn": {"expectsReply": expects_reply, "closesThread": closes_thread},
    }
    return sign(unsigned, sender)


def make_bridge(tmp_path, name, identities, *, allow=(), cards_for=None):
    """Build one bridge. ``identities`` are all agents in the registry.

    ``cards_for`` limits which senders this bridge holds cards for (default:
    everyone) — a sender with no card here is unknown, not merely untrusted.
    """
    identity = next(i for i in identities if i.agent_id.startswith(name + "@"))
    base = tmp_path / name
    base.mkdir(parents=True, exist_ok=True)
    policy = parse({
        "agent_id": identity.agent_id,
        "contact_policy": "closed",
        "deployment": "private",
        "allow": list(allow),
        "block": [],
        "limits": {},
    })
    contacts = Contacts(base / "contacts.db")
    threads = Threads(base / "threads.db")
    queue = Queue(base / "queue.db", identity.agent_id)
    gate = Gate(policy, contacts, threads)
    registry = registry_for(*identities)
    cards = {
        ident.agent_id: make_agent_card(ident, HUB, f"http://127.0.0.1/{ident.agent_id}")
        for ident in identities
        if cards_for is None or ident.agent_id in cards_for
    }
    bridge = Bridge(
        identity=identity, queue=queue, gate=gate, cards=cards, registry=registry
    ).start()
    return SimpleNamespace(
        identity=identity, bridge=bridge, queue=queue, gate=gate,
        contacts=contacts, threads=threads,
        url=bridge.url,
    )


def make_pair(tmp_path, *, muse_cards_for=None):
    """carl <-> muse, each allow-listing the other; mallory registered but a stranger."""
    carl_id = generate("carl", HUB)
    muse_id = generate("muse", HUB)
    mallory_id = generate("mallory", HUB)
    identities = [carl_id, muse_id, mallory_id]
    carl = make_bridge(tmp_path, "carl", identities, allow=[muse_id.agent_id])
    muse = make_bridge(
        tmp_path, "muse", identities, allow=[carl_id.agent_id],
        cards_for=muse_cards_for,
    )
    mallory = make_bridge(tmp_path, "mallory", identities, allow=[])
    return SimpleNamespace(
        carl=carl, muse=muse, mallory=mallory,
        carl_id=carl_id, muse_id=muse_id, mallory_id=mallory_id,
    )


def close_pair(pair):
    for agent in (pair.carl, pair.muse, pair.mallory):
        agent.bridge.stop()
        agent.queue.close()
        agent.contacts.close()
        agent.threads.close()
