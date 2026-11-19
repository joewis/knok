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

from .agentcard import verify_card
from .bridge import BridgeState, fingerprint_key, load_cards
from .envelope import sign
from .hubclient import HubClient, HubError, HubRefused
from .identity import b64url_decode, load as load_identity
from .recv import recv_once


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


def _verified_card(document: Any, agent_id: str) -> tuple[dict[str, Any] | None, str]:
    """The card body, but only if its own signature verifies *and* it names ``agent_id``.

    Deliberately not ``card_body``: that helper calls ``verify_card`` and discards the answer, so it
    returns a tampered card as readily as a good one (#59). This is the one path where a card
    arrives from off-host, so it reads the result.
    """
    if not isinstance(document, dict):
        return None, "not a card"
    try:
        body = json.loads(b64url_decode(document.get("payload") or ""))
    except Exception:
        return None, "payload does not decode"
    if not isinstance(body, dict):
        return None, "payload is not an object"
    public_key = (body.get("bridge") or {}).get("publicKey")
    if not isinstance(public_key, str):
        return None, "no public key in the card"
    ok, reason = verify_card(document, {fingerprint_key(public_key): public_key})
    if not ok:
        return None, reason
    # §12's public id is ``name@hub-domain``, and that is what the card has to spell out: a card is
    # bound to an id by its own body, not by the name it was fetched under.
    bridge = body.get("bridge") or {}
    name, hub_domain = body.get("name"), bridge.get("hub")
    claimed = (
        f"{name}@{hub_domain}" if isinstance(name, str) and isinstance(hub_domain, str) else None
    )
    if claimed != agent_id:
        return None, f"it is the card for {claimed or 'an unnamed agent'}"
    return body, ""


def _learn_card(state: BridgeState, identity, agent_id: str) -> None:
    """Ask the hub for a card this registry predates, and pin it for this process (#57).

    The local registry is a snapshot unpacked from ``registry.tgz``; the hub is the namespace
    authority (§4) and holds the live one. Refusing locally meant a newly registered agent was
    unreachable — *and* unverifiable — until an operator re-issued the tarball by hand, while the
    hub had the card all along.

    Two things this deliberately does not do:

    * It does not trust the document because the hub sent it. The card is fetched over the same
      channel as everything else and must still pass ``card_body``'s own signature check, and the
      body it decodes must name the id we asked for. Over a loopback or tailnet hop that is a
      meaningful check against a mangled answer and a meaningless one against a hostile hub — §4's
      answer to that is TLS plus a pinned hub key, which is not built yet, so this is exactly as
      strong as the channel. Written down here rather than implied.
    * It does not persist. The pin lasts for this invocation; the next ``send`` asks again. Making
      the registry self-updating is a cache with an eviction question (#54 covers the bridge side),
      and a stale cache is the bug this fixes.
    """
    try:
        document = HubClient(state.hub_url, identity).card(agent_id)
    except HubError as exc:
        raise SystemExit(f"cannot reach the hub to look up {agent_id}: {exc}")
    if document is None:
        raise SystemExit(
            f"{agent_id} is not registered with the hub; refusing to send into the void"
        )
    body, why = _verified_card(document, agent_id)
    if body is None:
        raise SystemExit(
            f"the hub sent a card for {agent_id} that cannot be trusted ({why}); refusing"
        )
    state.registry[agent_id] = body
    print(
        f"{agent_id} was not in the local registry; learned its card from the hub",
        file=sys.stderr,
    )


def cmd_send(args: argparse.Namespace) -> int:
    state, identity = _state_from_env()
    recipient = args.to
    if recipient not in state.registry:
        _learn_card(state, identity, recipient)

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
    state, identity = _state_from_env()
    count = recv_once(state, identity, limit=args.limit)
    sys.stderr.write(f"{count} message(s)\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="knok")
    sub = parser.add_subparsers(dest="command", required=True)

    send = sub.add_parser("send", help="sign and deposit one message")
    send.add_argument("--to", required=True)
    send.add_argument("--text", required=True)
    send.add_argument("--context", default=None)
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
