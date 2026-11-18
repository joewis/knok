"""`knok recv`: pull one batch straight from the hub and print it.

The bridge exists for agents that run a process. Some agents cannot: a sandboxed agent has no
socket, and an agent that only exists for the duration of a job has nowhere to keep a poll loop.
For those, a one-shot fetch is the only shape available — and it is a different contract from the
bridge, so it says so loudly rather than pretending to be one.

What it does: sign a `GET /v1/mail`, print each envelope as one JSON line on stdout, then ack the
batch. Acking after printing means the caller's stdout is the durable sink; if that stdout is not
durable, the message is lost on the next failure. The bridge solves this with a local queue and an
fsync before ack; this command has nowhere to put a queue, so it does not offer at-least-once.

It also bypasses the queue's `seq` ordering and dedupe: a `recv` and a bridge on the same identity
would fight, and a repeated `recv` after a lost stdout can see a message twice before the ack lands.
Use it when there is no daemon and the output goes somewhere that keeps it.

    KNOK_AGENT=sunny@knok.local KNOK_STATE=~/.knok KNOK_HUB_URL=http://hub:8080 \\
        python -m knok.cli recv --limit 20
"""

from __future__ import annotations

import json
import sys

from .bridge import BridgeState, fingerprint_key, load_cards
from .hubclient import HubClient
from .identity import load as load_identity


def recv_once(agent_id: str, state_dir, hub_url: str, registry_dir, limit: int = 20) -> int:
    """Fetch, print and ack one batch. Returns the number of envelopes handed out."""
    from pathlib import Path

    state = BridgeState(agent_id=agent_id, directory=Path(state_dir), hub_url=hub_url,
                        registry=load_cards(registry_dir))
    identity = load_identity(agent_id, state.key_path,
                             fingerprint_key(state.registry[agent_id]["bridge"]["publicKey"]))
    client = HubClient(hub_url, identity)
    body = client.fetch(limit=limit)
    envelopes = body.get("messages") or body.get("envelopes") or []
    message_ids: list[str] = []
    for envelope in envelopes:
        sys.stdout.write(json.dumps(envelope, sort_keys=True) + "\n")
        message = envelope.get("message") if isinstance(envelope, dict) else None
        if isinstance(message, dict) and isinstance(message.get("messageId"), str):
            message_ids.append(message["messageId"])
    sys.stdout.flush()
    if message_ids:
        client.ack(message_ids)
    return len(envelopes)
