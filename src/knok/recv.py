"""`knok recv`: pull one batch straight from the hub and print it.

The bridge exists for agents that run a process. Some agents cannot: a sandboxed agent has no
socket, and an agent that only exists for the duration of a job has nowhere to keep a poll loop.
For those, a one-shot fetch is the only shape available — and it is a different contract from the
bridge, so it says so loudly rather than pretending to be one.

What it does: sign a `GET /v1/mail`, print each envelope as one JSON line on stdout, then ack the
batch. Acking after printing means the caller's stdout is the durable sink; if that stdout is not
durable, the message is lost on the next failure. The bridge solves this with a local queue and an
fsync before ack; this command has nowhere to put a queue, so it does not offer at-least-once.

A hub transport frame (`expired`) is in the same mailbox as mail and must be acked the same way,
by the `messageId` it carries at the top level rather than inside `message`; an unacked frame is
re-printed by every later `recv` until the frame TTL sweeps it.

It also bypasses the queue's `seq` ordering and dedupe: a `recv` and a bridge on the same identity
would fight, and a repeated `recv` after a lost stdout can see a message twice before the ack lands.
Use it when there is no daemon and the output goes somewhere that keeps it.

    KNOK_AGENT=sunny@knok.local KNOK_STATE=~/.knok KNOK_HUB_URL=http://hub:8080 \\
        python -m knok.cli recv --limit 20
"""

from __future__ import annotations

import json
import sys

from .bridge import BridgeState
from .hubclient import HubClient
from .identity import Identity


def _ack_id(envelope: object) -> str | None:
    """The id an ack must carry for this row, or ``None`` when it carries none.

    A peer envelope nests it as ``message.messageId``. A hub transport frame (``expired``) is not a
    Message and has no ``message`` key: the id of the envelope it reports sits at the top level, and
    the hub files that frame in the mailbox under exactly that id — so it is what an ack deletes.
    """
    if not isinstance(envelope, dict):
        return None
    message = envelope.get("message")
    if isinstance(message, dict) and isinstance(message.get("messageId"), str):
        return message["messageId"]
    top_level = envelope.get("messageId")
    return top_level if isinstance(top_level, str) else None


def recv_once(state: BridgeState, identity: Identity, limit: int = 20) -> int:
    """Fetch, print and ack one batch. Returns the number of envelopes handed out.

    Both the state and the already-loaded identity are supplied by the caller: an identity is only
    trustworthy once it is bound to the registry's fingerprint (§4, no trust-on-first-use), and that
    binding belongs where the registry is read, not in here.
    """
    client = HubClient(state.hub_url, identity)
    body = client.fetch(limit=limit)
    envelopes = body.get("messages") or body.get("envelopes") or []
    message_ids: list[str] = []
    for envelope in envelopes:
        sys.stdout.write(json.dumps(envelope, sort_keys=True) + "\n")
        ack_id = _ack_id(envelope)
        if ack_id is not None:
            message_ids.append(ack_id)
    sys.stdout.flush()
    if message_ids:
        client.ack(message_ids)
    return len(envelopes)
