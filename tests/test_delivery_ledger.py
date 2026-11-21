"""The delivery ledger: a fetched message has a place to be seen (#79).

#79's shape is a message the sender holds, the hub no longer holds, and the receiving side has no
record of: 11 of Muse's 30 sends were in her ledger and nowhere in `inbox.jsonl`. The queue knew one
of the ids (`seen` had it) and held no message for it, which is what a *silent* decision looks like:
``queue.put`` answered ``duplicate``, the bridge reported that as ``queued``, and the hub was acked.

The fix is a record with an ordering guarantee, not a new policy: every fetched item leaves one row
in ``delivery.jsonl`` saying what was decided about it, and the rows are on disk *before* the ack
that lets the hub delete its copy. These tests hold that line:

* a delivered message has a row that was already written when the ack was sent;
* a message the queue refuses to store is a ``duplicate`` row — the loss is now visible, and the
  test reproduces the actual #79 sequence (two sends, one context, ``seq`` 0 both times);
* an item left at the hub says ``unhandled``, an item past its attempt allowance says ``dropped``;
* a ledger that cannot be written acks nothing, so a full disk cannot become the loss the ledger
  exists to catch.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from knok.bridge import MAX_HANDLE_ATTEMPTS
from knok.envelope import sign
from knok.hubclient import HubClient

from test_phase2 import deployment, iso, now  # noqa: F401  (fixture used by name)


def rows(agent) -> list[dict]:
    """The ledger this agent's bridge has written, in order."""
    path = agent.state.directory / "delivery.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def deposit(sender, recipient_id: str, text: str, *, context: str, message_id: str,
            seq: int = 0, expects_reply: bool = False):
    """Put one envelope in a mailbox the way `knok send` does, with the fields spelled out.

    ``seq`` and ``expects_reply`` are parameters here because the #79 sequence needs the same
    ``seq`` twice in one context and no reply credit in the way: the sender-side defect is that
    nothing mints a new ``seq`` for a second message in an existing thread.
    """
    moment = now()
    unsigned = {
        "envelopeVersion": 1,
        "seq": seq,
        "message": {
            "kind": "message",
            "messageId": message_id,
            "contextId": context,
            "role": "agent",
            "parts": [{"kind": "text", "text": text}],
        },
        "from": sender.identity.agent_id,
        "to": [recipient_id],
        "sentAt": iso(moment - timedelta(seconds=1)),
        "expiresAt": iso(moment + timedelta(hours=72)),
        "turn": {"expectsReply": expects_reply, "closesThread": False},
    }
    envelope = sign(unsigned, sender.identity)
    client = HubClient(sender.state.hub_url, sender.identity)
    return client.deposit(envelope), envelope


def test_a_delivered_message_is_recorded_before_the_hub_may_forget_it(deployment):
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    deposit(carl, muse.identity.agent_id, "review this", context="c-1", message_id="m-one")

    at_ack: list[list[dict]] = []
    original = muse.client.ack

    def ack(message_ids):
        # Read the file at the moment the hub is told to drop its copy: the row must already be
        # there, or the ack has destroyed the only evidence the message arrived.
        at_ack.append(rows(muse))
        return original(message_ids)

    muse.client.ack = ack
    counts = muse.poll_once()

    assert counts["fetched"] == 1 and counts["queued"] == 1
    assert at_ack and at_ack[0], "the ledger must be written before the hub ack"
    assert at_ack[0][-1]["messageId"] == "m-one"
    assert at_ack[0][-1]["outcome"] == "queued"
    assert at_ack[0][-1]["contextId"] == "c-1" and at_ack[0][-1]["seq"] == 0
    assert at_ack[0][-1]["from"] == carl.identity.agent_id
    assert muse.client.fetch()["messages"] == [], "the acked message must be gone from the hub"


def test_a_message_the_queue_will_not_store_is_recorded_as_a_duplicate(deployment):
    """#79 in one test: sent, accepted by the hub, acked, never in the inbox — now with a record.

    Both sends carry ``seq`` 0, because that is what the sender mints for a second message in an
    existing context. The queue has already delivered ``seq`` 0 for that stream, so the second is
    answered ``duplicate`` and stored nowhere. Before the ledger, the only trace was a ``seen`` row
    with no message beside it; the count said ``queued`` and the hub deleted its copy.
    """
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

    deposit(carl, muse.identity.agent_id, "first", context="c-thread", message_id="m-first")
    assert muse.poll_once()["queued"] == 1
    delivered = muse.queue.get()
    assert delivered is not None, "the first message must be deliverable"
    muse.queue.ack(delivered["message"]["messageId"])  # advances the stream to seq 1

    deposit(carl, muse.identity.agent_id, "second", context="c-thread", message_id="m-second")
    counts = muse.poll_once()

    assert counts["fetched"] == 1
    assert counts["duplicate"] == 1, "the queue refused to store it and the poll must say so"
    assert counts["queued"] == 0, "reporting this as queued is the defect #79 could not see"
    assert muse.queue.get() is None, "nothing may reach the application"
    assert muse.client.fetch()["messages"] == [], "the hub dropped it on the strength of our ack"

    lost = [row for row in rows(muse) if row["messageId"] == "m-second"]
    assert lost, "a message the hub no longer holds must have a row"
    assert lost[-1]["outcome"] == "duplicate"
    assert lost[-1]["contextId"] == "c-thread" and lost[-1]["seq"] == 0
    assert muse.queue.seen("m-second") is True, "the id is in seen with no message — the #79 shape"


def test_an_item_left_at_the_hub_says_so_and_is_not_acked(deployment):
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    # A card that cannot be found is the ordinary unhandled case: the envelope stays at the hub.
    del muse.state.registry[carl.identity.agent_id]
    deposit(carl, muse.identity.agent_id, "stranger", context="c-9", message_id="m-no-card")

    counts = muse.poll_once()

    assert counts["unhandled"] == 1 and counts["queued"] == 0
    assert [row["outcome"] for row in rows(muse)] == ["unhandled"]
    assert rows(muse)[0]["messageId"] == "m-no-card"
    assert len(muse.client.fetch()["messages"]) == 1, "an unhandled item is left for the next poll"


def test_the_attempt_allowance_is_spent_and_the_drop_is_recorded(deployment):
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    del muse.state.registry[carl.identity.agent_id]
    deposit(carl, muse.identity.agent_id, "never verifiable", context="c-4", message_id="m-doomed")

    outcomes = []
    for _ in range(MAX_HANDLE_ATTEMPTS):
        muse.poll_once()
        outcomes.append(rows(muse)[-1]["outcome"])

    assert outcomes[: MAX_HANDLE_ATTEMPTS - 1] == ["unhandled"] * (MAX_HANDLE_ATTEMPTS - 1)
    assert outcomes[-1] == "dropped", "the last attempt destroys it, and the ledger names it"
    assert muse.client.fetch()["messages"] == [], "a dropped item is acknowledged away"
    dropped = (muse.state.directory / "dropped.jsonl").read_text().splitlines()
    assert dropped, "the drop must still be recorded"
    assert "item" not in json.loads(dropped[0]), "the drop record is metadata only (#122)"


def test_a_ledger_that_cannot_be_written_acks_nothing(deployment):
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    deposit(carl, muse.identity.agent_id, "holds mail", context="c-5", message_id="m-held")
    path: Path = muse.state.directory / "delivery.jsonl"
    path.mkdir()  # a directory where the ledger belongs: every append raises OSError

    counts = muse.poll_once()

    assert counts["unhandled"] == 1 and counts["queued"] == 0
    assert len(muse.client.fetch()["messages"]) == 1, "no ack without a row: the hub keeps the copy"

    path.rmdir()
    counts = muse.poll_once()
    # The message is in the queue already: the retry is a duplicate the queue can recognise, and
    # the row says so. Nothing was lost while the ledger was unwritable — that is the whole point.
    assert counts["duplicate"] == 1
    assert muse.queue.get() is not None, "the message itself was never lost"
    assert rows(muse)[-1]["messageId"] == "m-held"
