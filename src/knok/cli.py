"""`knok send` / `knok inbox`: the two things a human or a runtime needs from inside an agent.

`send` is safe to run while the bridge daemon is polling: it only touches the identity and the hub,
never the queue, so it cannot fight the daemon for the queue lock. `inbox` reads what the daemon has
already handed to the application (`inbox.jsonl`), for the same reason.

    KNOK_AGENT=carl@hub.local KNOK_STATE=/app/state KNOK_REGISTRY=/app/registry \\
        KNOK_HUB_URL=http://hub:8080 python -m knok.cli send --to muse@hub.local --text "hello"

A message's thread lives in `--context`; a reply carries the same context so the queue can pair it
with what it answers. `seq` starts at 0 for a new context and the bridge's queue enforces ordering
for everything that follows.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .bridge import BridgeState, fingerprint_key, load_cards
from .envelope import sign
from .hubclient import HubClient, HubError, HubRefused
from .recv import recv_once
from .identity import load as load_identity


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _state_from_env() -> tuple[BridgeState, Any]:
    agent_id = os.environ.get("KNOK_AGENT")
    if not agent_id:
        raise SystemExit("KNOK_AGENT is required (e.g. carl@hub.local)")
    directory = Path(os.environ.get("KNOK_STATE", "/app/state"))
    hub_url = os.environ.get("KNOK_HUB_URL")
    if not hub_url:
        raise SystemExit("KNOK_HUB_URL is required")
    registry_dir = Path(os.environ.get("KNOK_REGISTRY", "/app/registry"))
    cards = load_cards(registry_dir)
    if agent_id not in cards:
        raise SystemExit(f"{agent_id} has no card in {registry_dir}")
    identity = load_identity(
        agent_id, directory / "identity.key", fingerprint_key(cards[agent_id]["bridge"]["publicKey"])
    )
    return BridgeState(agent_id=agent_id, directory=directory, hub_url=hub_url, registry=cards), identity


def cmd_send(args: argparse.Namespace) -> int:
    state, identity = _state_from_env()
    recipient = args.to
    if recipient not in state.registry:
        raise SystemExit(f"{recipient} is not in the registry; refusing to send into the void")

    moment = datetime.now(timezone.utc)
    message_id = args.message_id or f"m-{uuid.uuid4().hex}"
    unsigned: dict[str, Any] = {
        "envelopeVersion": 1,
        "seq": args.seq,
        "message": {
            "kind": "message",
            "messageId": message_id,
            "contextId": args.context or f"c-{uuid.uuid4().hex}",
            "role": "agent",
            "parts": [{"kind": "text", "text": args.text}],
            **({"replyTo": args.reply_to} if args.reply_to else {}),
        },
        "from": identity.agent_id,
        "to": [recipient],
        "sentAt": _iso(moment),
        "expiresAt": _iso(moment + timedelta(hours=args.ttl_hours)),
        "turn": {"expectsReply": args.expects_reply, "closesThread": args.closes_thread},
    }
    envelope = sign(unsigned, identity)

    client = HubClient(state.hub_url, identity)
    for attempt in range(1, 4):
        try:
            result = client.deposit(envelope)
            print(json.dumps({"messageId": message_id, **result}, sort_keys=True))
            return 0
        except HubRefused as exc:
            # 429 is the hub saying "mailbox full, try later" — the one retryable refusal.
            if exc.retryable and attempt < 3:
                import time

                time.sleep(2 * attempt)
                continue
            print(f"hub refused the message: {exc.status}", file=sys.stderr)
            return 2
        except HubError as exc:
            print(f"cannot reach the hub: {exc}", file=sys.stderr)
            return 3
    return 3


def cmd_inbox(args: argparse.Namespace) -> int:
    directory = Path(os.environ.get("KNOK_STATE", "/app/state"))
    path = directory / "inbox.jsonl"
    if not path.exists():
        print("inbox is empty", file=sys.stderr)
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()
    selected = lines[-args.limit :]
    for line in selected:
        if args.json:
            print(line)
            continue
        envelope = json.loads(line)
        message = envelope.get("message", {})
        text = "".join(
            part.get("text", "") for part in message.get("parts", []) if part.get("kind") == "text"
        )
        print(f"{envelope.get('sentAt')}  {envelope.get('from')}  [{message.get('contextId')}]")
        print(f"  {text}")
    return 0


def cmd_recv(args: argparse.Namespace) -> int:
    agent_id = os.environ.get("KNOK_AGENT")
    hub_url = os.environ.get("KNOK_HUB_URL")
    if not agent_id or not hub_url:
        raise SystemExit("KNOK_AGENT and KNOK_HUB_URL are required")
    count = recv_once(
        agent_id,
        os.environ.get("KNOK_STATE", "/app/state"),
        hub_url,
        os.environ.get("KNOK_REGISTRY", "/app/registry"),
        limit=args.limit,
    )
    sys.stderr.write(f"{count} message(s)\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="knok")
    sub = parser.add_subparsers(dest="command", required=True)

    send = sub.add_parser("send", help="sign and deposit one message")
    send.add_argument("--to", required=True)
    send.add_argument("--text", required=True)
    send.add_argument("--context", default=None)
    send.add_argument("--reply-to", default=None)
    send.add_argument("--message-id", default=None)
    send.add_argument("--seq", type=int, default=0)
    send.add_argument("--ttl-hours", type=int, default=72)
    send.add_argument("--expects-reply", action="store_true", default=True)
    send.add_argument("--no-reply", dest="expects_reply", action="store_false")
    send.add_argument("--closes-thread", action="store_true", default=False)
    send.set_defaults(func=cmd_send)

    recv = sub.add_parser("recv", help="fetch straight from the hub (no daemon; see knok/recv.py)")
    recv.add_argument("--limit", type=int, default=20)
    recv.set_defaults(func=cmd_recv)

    inbox = sub.add_parser("inbox", help="what the daemon has delivered to this agent")
    inbox.add_argument("--limit", type=int, default=20)
    inbox.add_argument("--json", action="store_true")
    inbox.set_defaults(func=cmd_inbox)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
