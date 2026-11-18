"""Two bridges on loopback in one process (SPEC §6, §11; issue #21).

Run from the repo root::

    PYTHONPATH=src python examples/two_agents.py

carl sends to muse with ``turn.expectsReply`` true, muse replies, carl closes
the thread. Then the three proofs, printed with real observed values — a
refusal's exact status and body, a queue depth, a delivered message — not
assertions dressed as output.

Turn-taking note: muse's reply carries ``expectsReply: true`` because carl's
closing message is a further message in the thread, and the gate only admits
a message the receiver invited (§6). The close itself is what shuts the
thread: after it, carl's gate refuses anything more in that context.
"""

from __future__ import annotations

import json
import secrets
import tempfile
from pathlib import Path

from knok.contacts import Contacts
from knok.envelope import sign
from knok.gate import Gate, Threads
from knok.identity import generate
from knok.policy import parse
from knok.queue import Queue
from knok.transport import (
    REFUSAL_BODY,
    REFUSAL_STATUS,
    Bridge,
    make_agent_card,
    post_envelope,
    registry_for,
)

HUB = "bridge.example"
CONTEXT = "demo-1"
SENT_AT = "2026-11-18T05:00:00Z"
EXPIRES_AT = "2026-11-21T05:00:00Z"


def new_message_id() -> str:
    return "m-" + secrets.token_hex(16)  # 128 bits from a CSPRNG (§6)


def build_envelope(sender, recipient_id, *, seq, context_id=CONTEXT,
                   text, expects_reply, closes_thread):
    unsigned = {
        "envelopeVersion": 1,
        "seq": seq,
        "message": {
            "kind": "message",
            "messageId": new_message_id(),
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


def make_bridge(base: Path, name, identities, *, allow):
    identity = next(i for i in identities if i.agent_id.startswith(name + "@"))
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
    cards = {
        ident.agent_id: make_agent_card(ident, HUB, f"http://127.0.0.1/{ident.agent_id}")
        for ident in identities
    }
    bridge = Bridge(
        identity=identity, queue=queue, gate=gate,
        cards=cards, registry=registry_for(*identities),
    ).start()
    return bridge, queue, (contacts, threads)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="knok-demo-") as tmp:
        root = Path(tmp)
        carl_id = generate("carl", HUB)
        muse_id = generate("muse", HUB)
        mallory_id = generate("mallory", HUB)
        identities = [carl_id, muse_id, mallory_id]

        carl, carl_queue, carl_state = make_bridge(
            root / "carl", "carl", identities, allow=[muse_id.agent_id])
        muse, muse_queue, muse_state = make_bridge(
            root / "muse", "muse", identities, allow=[carl_id.agent_id])
        try:
            # 1. carl -> muse, expecting a reply.
            opening = build_envelope(
                carl_id, muse_id.agent_id, seq=0,
                text="Can you review §4?", expects_reply=True, closes_thread=False)
            ack = carl.send(muse.url, opening)
            print(f"carl -> muse: ack kind={ack['kind']} "
                  f"messageId={ack['messageId']} seq={ack['seq']}")
            print(f"muse queue depth after delivery: {muse_queue.depth()}")

            # Proof 2 (shown here, while the thread is still open: a
            # retransmission of the opening must be acked, stored once).
            again = carl.send(muse.url, opening)
            print(f"duplicate resend: ack kind={again['kind']} "
                  f"messageId={again['messageId']}")
            print(f"proof 2 — muse queue depth after duplicate: {muse_queue.depth()}")
            delivered = muse_queue.get()
            print(f"proof 2 — muse queue holds messageId="
                  f"{delivered['message']['messageId']} "
                  f"(opening was {opening['message']['messageId']})")
            muse_queue.ack(delivered["message"]["messageId"])
            print(f"muse queue depth after acking the opening: {muse_queue.depth()}")

            # 2. muse replies, inviting carl's close.
            reply = build_envelope(
                muse_id, carl_id.agent_id, seq=0,
                text="§4 reviewed: the signature covers the whole envelope.",
                expects_reply=True, closes_thread=False)
            ack = muse.send(carl.url, reply)
            print(f"muse -> carl: ack kind={ack['kind']} "
                  f"messageId={ack['messageId']} seq={ack['seq']}")
            print(f"carl queue depth after reply: {carl_queue.depth()}")

            # 3. carl closes the thread.
            closing = build_envelope(
                carl_id, muse_id.agent_id, seq=1,
                text="Thanks — closing this thread.",
                expects_reply=False, closes_thread=True)
            ack = carl.send(muse.url, closing)
            print(f"carl -> muse (close): ack kind={ack['kind']} "
                  f"messageId={ack['messageId']} seq={ack['seq']}")
            print(f"muse queue depth after close: {muse_queue.depth()}")

            # Proof 1: a stranger (mallory is registered, but no contact)
            # is refused with the shared string.
            stranger = build_envelope(
                mallory_id, muse_id.agent_id, seq=0, context_id="demo-9",
                text="Hello, I am definitely carl's friend.",
                expects_reply=False, closes_thread=False)
            status, body = post_envelope(muse.url, json.dumps(stranger).encode())
            print(f"proof 1 — stranger refused: status={status} "
                  f"body={body.decode()} "
                  f"(shared refusal is {REFUSAL_STATUS} {REFUSAL_BODY.decode()})")
            print(f"muse queue depth after stranger: {muse_queue.depth()}")

            # Proof 3: the closed thread refuses a further message.
            after_close = build_envelope(
                muse_id, carl_id.agent_id, seq=1,
                text="One more thing —", expects_reply=False, closes_thread=False)
            status, body = post_envelope(carl.url, json.dumps(after_close).encode())
            print(f"proof 3 — closed thread refused: status={status} "
                  f"body={body.decode()}")
            print(f"carl queue depth after closed-thread attempt: {carl_queue.depth()}")
        finally:
            carl.stop()
            muse.stop()
            carl_queue.close()
            muse_queue.close()
            for store in (*carl_state, *muse_state):
                store.close()


if __name__ == "__main__":
    main()
