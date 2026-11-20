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
from .retry import (
    NOTICE_TIMES,
    SENT_LEDGER,
    decide_notice,
    due,
    read_attempts,
    read_notices,
    read_retries,
    record_retry,
    terminal_record,
)


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


def _retry_envelope(
    state: BridgeState, identity, message_id: str
) -> tuple[int, dict[str, Any] | None, dict[str, Any] | None]:
    """Re-deposit a stored attempt, without printing. Returns (status, result, envelope).

    The ``knok retry`` command uses this directly so it can format the outcome itself; the
    ``send --retry-of`` path keeps its own printing in ``_retry`` below.
    """
    envelope = _find_attempt(state, message_id)
    if envelope is None:
        print(
            f"no attempt {message_id} in {_ledger_path(state)}: a retry repeats an attempt this "
            "agent actually made, and only its own record can say which thread that was",
            file=sys.stderr,
        )
        return 4, None, None
    if envelope.get("from") != identity.agent_id:
        print(f"{message_id} was sent by {envelope.get('from')}, not by me", file=sys.stderr)
        return 4, None, None
    status, result = _try_deposit(HubClient(state.hub_url, identity), envelope)
    return status, result, envelope


def _retry(state: BridgeState, identity, args: argparse.Namespace) -> int:
    """Re-deposit an earlier attempt verbatim, so its thread survives the retry (#48).

    A retry that mints a new ``contextId`` fragments the conversation: the peer answers a thread
    that started at the retry instead of continuing the one the first attempt opened. The stored
    envelope already carries the context, the seq and the signature, so repeating it is a replay,
    not a rewrite — the hub answers "duplicate" when the first copy is still queued, and the
    recipient's queue dedupes by ``messageId`` when it is not.
    """
    status, result, envelope = _retry_envelope(state, identity, args.retry_of)
    if result is not None and envelope is not None:
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
    # ``selected[-limit:]`` with limit 0 is ``selected[0:]`` — everything — and a negative limit
    # silently drops notices from the front. A limit is a count of the newest notices, so anything
    # below 1 is a usage error, not a way to ask for all of them.
    if args.limit < 1:
        print(f"--limit must be at least 1, got {args.limit}", file=sys.stderr)
        return 2
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


def _retry_outcome(
    notice: dict[str, Any],
    decision: str,
    reason: str,
    attempt: int,
    not_before: datetime | None,
) -> dict[str, Any]:
    """One message's retry decision, in the shape ``knok retry`` prints (and --json emits)."""
    outcome: dict[str, Any] = {
        "messageId": notice.get("messageId"),
        "contextId": notice.get("contextId"),
        "kind": notice.get("kind"),
        "rule": notice.get("rule"),
        "decision": decision,
        "reason": reason,
        "attempt": attempt,
        "notBefore": _iso(not_before) if not_before is not None else None,
    }
    return outcome


def _retry_line(outcome: dict[str, Any]) -> str:
    """One decision as a line a human can scan."""
    message_id = outcome.get("messageId")
    decision = outcome.get("decision")
    if decision == "retry":
        if "status" not in outcome:
            # A dry run, or a retry the command could not perform: the policy said retry,
            # but no deposit was attempted, so there is no exit code to report.
            return f"would retry {message_id} (attempt {outcome.get('attempt')})"
        status = outcome.get("status")
        result = outcome.get("result")
        if status == 0 and isinstance(result, dict):
            word = "accepted" if result.get("accepted") else "duplicate" if result.get("duplicate") else "ok"
            return f"retried {message_id} (attempt {outcome.get('attempt')}): {word}"
        return f"retried {message_id} (attempt {outcome.get('attempt')}): failed, exit {status}"
    if decision == "waiting":
        return (
            f"waiting {message_id}: retry due at {outcome.get('notBefore')} "
            f"(attempt {outcome.get('attempt')})"
        )
    return f"terminal {message_id}: {outcome.get('reason')}"


def _retry_record(
    notice: dict[str, Any],
    decision,
    now: datetime,
    status: int | None = None,
) -> dict[str, Any]:
    """One line for ``retries.jsonl``: the decision, and, for a performed retry, its result."""
    record: dict[str, Any] = {
        "messageId": notice.get("messageId"),
        "contextId": notice.get("contextId"),
        "kind": notice.get("kind"),
        "rule": notice.get("rule"),
        "attempt": decision.attempt,
        "at": _iso(now),
        "decision": decision.action,
        "reason": decision.reason,
        "notBefore": _iso(decision.not_before) if decision.not_before is not None else None,
    }
    if status is not None:
        record["status"] = status
    return record


def cmd_retry(args: argparse.Namespace) -> int:
    """Apply the adapter's retry policy to the failures the bridge recorded (#48).

    ``knok notices`` reports which messages died; this decides which of them are worth
    repeating, and repeats the ones that are due. A retry replays the stored envelope verbatim
    (``send --retry-of``), so the thread survives — the policy never mints a fresh
    ``contextId``. Decisions are recorded in ``retries.jsonl`` so the budget is enforced and a
    decided message is not re-decided on every scan; a retry that is not yet due is reported
    as waiting and re-decided on the next scan.

    The scan runs in two phases. First it decides every message, which needs no hub: a
    terminal decision is recorded even when a retry elsewhere in the scan cannot be performed.
    Then it performs the retries that are due, which needs the identity and the hub. A scan
    that cannot load them still records its terminal decisions and reports the due retries as
    not performed, instead of dying on the first one.

    With ``--message-id`` it decides for one message; without it, it scans every notice.
    With ``--dry-run`` it reports decisions without performing retries or recording. With
    ``--json`` it prints one JSON object per message decided. In scan mode the exit code is 0
    when the scan completed, 1 when a due retry could not be performed; with ``--message-id``
    it is the retry's exit code when a retry was performed, else 0.
    """
    directory = Path(os.environ.get("KNOK_STATE", "/app/state"))
    now = datetime.now(timezone.utc)
    notices = read_notices(directory)
    attempts = read_attempts(directory)
    retries = read_retries(directory)

    # Latest notice per messageId, in file order. One messageId dies one death, so the latest
    # notice is the one that decides it.
    latest: dict[str, dict[str, Any]] = {}
    for notice in notices:
        message_id = notice.get("messageId")
        if isinstance(message_id, str) and message_id:
            latest[message_id] = notice

    if args.message_id:
        notice = latest.get(args.message_id)
        if notice is None:
            print(f"no delivery notice for {args.message_id}", file=sys.stderr)
            return 0
        targets = [(args.message_id, notice)]
    else:
        targets = sorted(latest.items())

    outcomes: list[dict[str, Any]] = []
    exit_code = 0
    # Phase one: decide every message. This needs no hub, so a terminal decision is recorded
    # even when a retry elsewhere in the scan cannot be performed.
    due_list: list[tuple[str, dict[str, Any], Any]] = []
    for message_id, notice in targets:
        # A message already decided terminal stays decided; the decision is stable, so
        # re-deciding it on every scan is noise.
        decided = terminal_record(retries, message_id)
        if decided is not None:
            outcomes.append(
                _retry_outcome(
                    notice,
                    "terminal",
                    str(decided.get("reason") or ""),
                    0,
                    None,
                )
            )
            continue
        envelope = attempts.get(message_id)
        decision = decide_notice(notice, envelope, retries, now)
        if decision.action == "terminal":
            outcomes.append(_retry_outcome(notice, "terminal", decision.reason, 0, None))
            if not args.dry_run:
                record = _retry_record(notice, decision, now)
                if record_retry(directory, record):
                    retries.append(record)
            continue
        # A retry. If it is not yet due, report it as waiting and re-decide it on the next
        # scan; a waiting decision is not recorded.
        if not due(decision, now):
            outcomes.append(
                _retry_outcome(
                    notice, "waiting", decision.reason, decision.attempt, decision.not_before
                )
            )
            continue
        if args.dry_run:
            outcomes.append(
                _retry_outcome(
                    notice, "retry", decision.reason, decision.attempt, decision.not_before
                )
            )
            continue
        due_list.append((message_id, notice, decision))

    # Phase two: perform the retries that are due. The identity and the hub are only needed
    # here, so a scan that decides nothing (or only waits) never touches them.
    if due_list:
        try:
            state, identity = _state_from_env()
        except SystemExit as exc:
            print(f"cannot retry: {exc}", file=sys.stderr)
            for message_id, notice, decision in due_list:
                outcomes.append(
                    _retry_outcome(
                        notice, "retry", decision.reason, decision.attempt, decision.not_before
                    )
                )
            exit_code = 1
        else:
            for message_id, notice, decision in due_list:
                status, result, _envelope = _retry_envelope(state, identity, message_id)
                outcome = _retry_outcome(
                    notice, "retry", decision.reason, decision.attempt, decision.not_before
                )
                outcome["status"] = status
                if result is not None:
                    outcome["result"] = result
                outcomes.append(outcome)
                record = _retry_record(notice, decision, now, status=status)
                if record_retry(directory, record):
                    retries.append(record)
                if args.message_id:
                    exit_code = status

    for outcome in outcomes:
        if args.json:
            print(json.dumps(outcome, sort_keys=True))
        else:
            print(_retry_line(outcome))
    return exit_code


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

    #: The adapter's retry policy (#48): which failures are worth repeating, and when. A retry
    #: replays the stored envelope verbatim, so the thread survives; the policy never mints a
    #: fresh contextId. Without --message-id it scans every notice; with --dry-run it reports
    #: decisions without performing retries or recording.
    retry = sub.add_parser("retry", help="retry the failures the bridge recorded, when the policy says to")
    retry.add_argument("--message-id", default=None, metavar="MESSAGE_ID")
    retry.add_argument("--dry-run", action="store_true")
    retry.add_argument("--json", action="store_true")
    retry.set_defaults(func=cmd_retry)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
