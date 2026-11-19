"""`knok send` / `knok inbox` / `knok notices`: what a human or a runtime needs from inside an agent.

`send` is safe to run while the bridge daemon is polling: it only touches the identity and the hub,
never the queue, so it cannot fight the daemon for the queue lock. `inbox` reads what the daemon has
already handed to the application (`inbox.jsonl`), for the same reason; `notices` reads the other
half of the same file pair — what the bridge learned about *our own* messages that did not arrive.

    KNOK_AGENT=carl@hub.local KNOK_STATE=/app/state KNOK_REGISTRY=/app/registry \\
        KNOK_HUB_URL=http://hub:8080 python -m knok.cli send --to muse@hub.local --text "hello"

A message's thread lives in `--context`; a reply carries the same context so the queue can pair it
with what it answers. `seq` starts at 0 for a new context and the bridge's queue enforces ordering
for everything that follows.

Every attempt is also written to `sent.jsonl` before it is deposited, and `--retry-of <messageId>`
re-deposits one of them *verbatim*. A retry that minted a fresh `contextId` would start a new thread
and split the conversation in two (#48); replaying the stored envelope keeps the thread, and the
hub's and the recipient's dedupe keep the replay from delivering twice.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .agentcard import verify_card
from .bridge import NOTICES, BridgeState, fingerprint_key, load_cards
from .envelope import sign
from .hubclient import HubClient, HubError, HubRefused
from .identity import b64url_decode, load as load_identity
from .recv import recv_once

#: Every attempt this agent deposited, with the signed envelope it deposited. ``--retry-of`` reads
#: it: only the sender knows which attempt it is repeating, so the sender has to keep the record.
SENT_LEDGER = "sent.jsonl"


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
    return BridgeState(
        agent_id=agent_id,
        directory=directory,
        hub_url=hub_url,
        registry=cards,
        registry_dir=registry_dir,
    ), identity


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
      channel as everything else and must still pass its own signature check (``_verified_card``),
      and the body it decodes must name the id we asked for. Over a loopback or tailnet hop that is
      a meaningful check against a mangled answer and a meaningless one against a hostile hub — §4's
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
    if args.retry_of:
        return _retry(state, identity, args)
    if not args.to or not args.text:
        raise SystemExit("send needs --to and --text (or --retry-of <messageId>)")
    recipient = args.to
    if recipient not in state.registry:
        _learn_card(state, identity, recipient)

    moment = datetime.now(timezone.utc)
    message_id = args.message_id or f"m-{uuid.uuid4().hex}"
    context = args.context or f"c-{uuid.uuid4().hex}"
    unsigned: dict[str, Any] = {
        "envelopeVersion": 1,
        "seq": args.seq,
        "message": {
            "kind": "message",
            "messageId": message_id,
            "contextId": context,
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
    # Recorded before the deposit, not after: an attempt that never reached the hub is exactly the
    # one the caller most needs to retry, and a record written afterwards would not exist for it.
    _remember_attempt(state, envelope)

    status, result = _try_deposit(HubClient(state.hub_url, identity), envelope)
    if result is not None:
        print(json.dumps({"messageId": message_id, "contextId": context, **result}, sort_keys=True))
    return status


def _try_deposit(client: HubClient, envelope: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
    """Deposit one envelope, retrying the only retryable refusal (429). Returns (exit code, reply)."""
    for attempt in range(1, 4):
        try:
            return 0, client.deposit(envelope)
        except HubRefused as exc:
            # 429 is the hub saying "mailbox full, try later" — the one retryable refusal.
            if exc.retryable and attempt < 3:
                time.sleep(2 * attempt)
                continue
            print(f"hub refused the message: {exc.status}", file=sys.stderr)
            return 2, None
        except HubError as exc:
            print(f"cannot reach the hub: {exc}", file=sys.stderr)
            return 3, None
    return 3, None


def _ledger_path(state: BridgeState) -> Path:
    return state.directory / SENT_LEDGER


def _remember_attempt(state: BridgeState, envelope: dict[str, Any]) -> bool:
    """Append one fsynced attempt record. False (and loud) when it cannot be written."""
    record = {"recordedAt": _iso(datetime.now(timezone.utc)), "envelope": envelope}
    path = _ledger_path(state)
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return True
    except OSError as exc:
        # Sending must not fail because bookkeeping did, so this warns instead of raising — but it
        # says exactly what was lost: this message will not be retryable.
        print(f"warning: could not record the attempt in {path}: {exc}", file=sys.stderr)
        return False


def _find_attempt(state: BridgeState, message_id: str) -> dict[str, Any] | None:
    """The last envelope this agent deposited under ``message_id``, or None."""
    try:
        lines = _ledger_path(state).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    found: dict[str, Any] | None = None
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        envelope = record.get("envelope") if isinstance(record, dict) else None
        if isinstance(envelope, dict) and (envelope.get("message") or {}).get("messageId") == message_id:
            found = envelope
    return found


def _retry(state: BridgeState, identity, args: argparse.Namespace) -> int:
    """Re-deposit an earlier attempt verbatim, so its thread survives the retry (#48).

    A retry that mints a new ``contextId`` fragments the conversation: the peer answers a thread
    that started at the retry instead of continuing the one the first attempt opened. The stored
    envelope already carries the context, the seq and the signature, so repeating it is a replay,
    not a rewrite — the hub answers "duplicate" when the first copy is still queued, and the
    recipient's queue dedupes by ``messageId`` when it is not.
    """
    envelope = _find_attempt(state, args.retry_of)
    if envelope is None:
        print(
            f"no attempt {args.retry_of} in {_ledger_path(state)}: a retry repeats an attempt this "
            "agent actually made, and only its own record can say which thread that was",
            file=sys.stderr,
        )
        return 4
    if envelope.get("from") != identity.agent_id:
        print(f"{args.retry_of} was sent by {envelope.get('from')}, not by me", file=sys.stderr)
        return 4
    status, result = _try_deposit(HubClient(state.hub_url, identity), envelope)
    if result is not None:
        message = envelope["message"]
        print(
            json.dumps(
                {
                    "messageId": message["messageId"],
                    "contextId": message["contextId"],
                    "retried": True,
                    **result,
                },
                sort_keys=True,
            )
        )
    return status


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


#: Every kind the bridge writes into ``notices.jsonl``, and so every kind this reader can be asked
#: to select. A filter that cannot name a line the reader prints is a hole in the same file.
NOTICE_KINDS = ("refused", "expired", "dead", "late", "gap")

#: Each kind dates itself with its own word: a refusal was ``receivedAt`` at the peer's gate, a dead
#: letter ``deadedAt`` here, a gap release ``releasedAt``. A reader that knew only one or two of
#: them would print ``?`` where the only copy of a failure should say when it happened.
NOTICE_TIMES = ("receivedAt", "expiredAt", "deadedAt", "detectedAt", "releasedAt", "at")


def _ranges(seqs: list[Any]) -> str:
    """``[3, 4, 5, 9]`` -> ``"3-5,9"``: a gap's column stays readable when it skipped many seqs."""
    numbers = sorted({int(seq) for seq in seqs if isinstance(seq, int)})
    if len(numbers) != len(seqs):
        return ",".join(str(seq) for seq in seqs)
    if not numbers:
        return ""
    parts: list[str] = []
    start = previous = numbers[0]
    for number in numbers[1:]:
        if number == previous + 1:
            previous = number
            continue
        parts.append(f"{start}-{previous}" if previous != start else str(start))
        start = previous = number
    parts.append(f"{start}-{previous}" if previous != start else str(start))
    return ",".join(parts)


def _notice_subject(notice: dict[str, Any]) -> str:
    """Which message the notice is about. A gap has no single message, so it names the seqs it skipped."""
    message_id = notice.get("messageId")
    if message_id:
        return str(message_id)
    missing = notice.get("missing")
    if isinstance(missing, list) and missing:
        return f"seqs {_ranges(missing)}"
    return "?"


def _notice_line(notice: dict[str, Any]) -> str:
    """One notice as a line a human can scan: when, who, which message, which thread, what.

    Every shape the bridge records must fill every column: a ``?`` here means the reader dropped a
    fact the file holds, which is the one thing a failure record must not do.
    """
    when = next((str(notice[key]) for key in NOTICE_TIMES if notice.get(key)), "?")
    rule = notice.get("rule")
    kind = str(notice.get("kind") or "?")
    return "  ".join(
        [
            when,
            # A dead letter's frame carries no sender — the queue knows it, the record does not —
            # so "-" says "not recorded" where "?" would say "the reader failed to find it".
            str(notice.get("from") or "-"),
            _notice_subject(notice),
            f"[{notice.get('contextId') or '-'}]",
            f"{kind} ({rule})" if rule else kind,
        ]
    )


def cmd_notices(args: argparse.Namespace) -> int:
    """Report what became of the messages this agent sent, as far as anything here can know.

    ``send`` exits 0 when the hub accepted the envelope; delivery can still fail afterwards, and
    the failure lands here — a refusal notice from the peer's gate (#50), the hub's own
    ``expired``/``dead`` frame, or the receiver's ``gap``/``late`` notice when a stream skipped or
    reordered messages. The bridge writes them as it learns them and never queues them, so this
    reads the same ``notices.jsonl`` the operator sees.

    It reports and does not act: whether to repeat an attempt, and how often, is a decision about
    the caller's own failure, so it belongs to the adapter. What this gives it is the one fact it
    cannot derive — which ``messageId`` died — which is exactly the argument ``send --retry-of``
    takes (#48).
    """
    path = Path(os.environ.get("KNOK_STATE", "/app/state")) / NOTICES
    if not path.exists():
        print("no delivery notices", file=sys.stderr)
        return 0
    selected: list[dict[str, Any]] = []
    unreadable = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            notice = json.loads(line)
        except ValueError:
            unreadable += 1
            continue
        if not isinstance(notice, dict):
            unreadable += 1
            continue
        if args.kind and notice.get("kind") != args.kind:
            continue
        selected.append(notice)
    # A torn or hand-edited line must not hide the rest: the file is the only copy of a failure,
    # so the reader says how much it could not read rather than dying or silently shrinking.
    if unreadable:
        print(f"skipped {unreadable} unreadable line(s) in {path}", file=sys.stderr)
    if not selected:
        wanted = f"{args.kind} notices" if args.kind else "delivery notices"
        print(f"no {wanted}", file=sys.stderr)
        return 0
    for notice in selected[-args.limit :]:
        print(json.dumps(notice, sort_keys=True) if args.json else _notice_line(notice))
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
    send.add_argument("--to", default=None)
    send.add_argument("--text", default=None)
    send.add_argument("--context", default=None)
    send.add_argument("--message-id", default=None)
    #: Repeat an attempt this agent already made, verbatim and in its original thread (#48). The
    #: caller that knows which attempt failed is the adapter, so the flag takes the messageId the
    #: failed attempt printed rather than making the caller guess a context id.
    send.add_argument("--retry-of", dest="retry_of", default=None, metavar="MESSAGE_ID")
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

    #: Reading the failure half of a send (#48): a refusal, an expiry, a dead letter. The command
    #: reports the messageId; repeating the attempt with --retry-of remains the caller's decision.
    notices = sub.add_parser("notices", help="what became of the messages this agent sent")
    notices.add_argument("--limit", type=int, default=20)
    notices.add_argument("--kind", choices=list(NOTICE_KINDS), default=None)
    notices.add_argument("--json", action="store_true")
    notices.set_defaults(func=cmd_notices)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
