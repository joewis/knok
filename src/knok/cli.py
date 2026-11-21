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
mints a new envelope for one of them. A retry that minted a fresh `contextId` would start a new
thread and split the conversation in two (#48); the new envelope keeps the thread — the same
`contextId`, the same `seq` (the original seq was never consumed), the same turn, role and parts
— and carries `retryOf` naming the original, so the receiver can correlate it with the failure.
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
    EXIT_RATE_LIMITED,
    NOTICE_TIMES,
    SENT_LEDGER,
    decide_notice,
    decide_send,
    due,
    envelope_expires_at,
    envelope_sent_at,
    notice_time,
    read_attempts,
    read_notices,
    read_retries,
    record_retry,
    resolved_record,
    retry_ledger_lock,
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
    # Always printed, success or failure: a send that never reached the hub still names the
    # message, and the adapter needs that id to retry it (#48). ``delivered`` is the one field
    # a caller needs — a failure prints no hub reply, so without it the caller could not tell
    # a failed send from a silent one.
    print(
        json.dumps(
            {
                "messageId": message_id,
                "contextId": context,
                "delivered": status == 0,
                **(result or {}),
                **({"status": status} if status != 0 else {}),
            },
            sort_keys=True,
        )
    )
    return status


def _try_deposit(client: HubClient, envelope: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
    """Deposit one envelope, retrying the only retryable refusal (429). Returns (exit code, reply).

    The exit code keeps a 403 and an exhausted 429 apart: a 403 is a permanent refusal (2),
    an exhausted 429 is rate-limited (5, retryable after the window). The reply carries the
    refusal's HTTP status, so the caller can tell which it was without decoding the code.
    """
    for attempt in range(1, 4):
        try:
            return 0, client.deposit(envelope)
        except HubRefused as exc:
            # 429 is the hub saying "mailbox full, try later" — the one retryable refusal.
            if exc.retryable and attempt < 3:
                time.sleep(2 * attempt)
                continue
            print(f"hub refused the message: {exc.status}", file=sys.stderr)
            if exc.retryable:
                # The 429 survived the in-process retries. This is not a permanent refusal:
                # the window clears, so the adapter retries it after the window (see
                # decide_send). A distinct exit code, so the caller does not have to guess
                # whether a 2 was a 403 or a 429 it could have waited out.
                return EXIT_RATE_LIMITED, {"refusalStatus": exc.status}
            return 2, {"refusalStatus": exc.status}
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
    """The last envelope this agent deposited under ``message_id``, or None.

    A ledger the reader cannot decode (a torn write, a byte that is not valid UTF-8) is
    read as no attempt, not as a crash: a retry that cannot find its attempt exits 4,
    and the scan that depends on it must not die on bookkeeping.
    """
    try:
        lines = _ledger_path(state).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
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


def _mint_retry_envelope(
    original: dict[str, Any], identity, now: datetime
) -> dict[str, Any]:
    """Mint the retry's envelope from the stored attempt: new id, same thread and seq.

    A retry stops replaying identical bytes. The original ``messageId`` is in ``seen`` (or
    never arrived at all), so the retry mints a new one and carries ``retryOf`` naming the
    original in ``message.metadata`` — the audit trail, and what lets the receiver correlate
    the retry with the failure. Everything else is the original's: the same ``contextId``,
    the same ``seq`` (it was never consumed, so ``seq+1`` would open an unfillable gap),
    the same turn, role and parts, the same recipients. ``sentAt``/``expiresAt`` are fresh
    — now plus the original envelope's TTL duration — and the envelope is signed anew, so a
    signature the hub refused does not survive into the retry.
    """
    message = original["message"]
    sent = envelope_sent_at(original)
    expires = envelope_expires_at(original)
    ttl = (expires - sent) if sent is not None and expires is not None else timedelta(hours=72)
    metadata = dict(message.get("metadata") or {})
    metadata["retryOf"] = message["messageId"]
    unsigned: dict[str, Any] = {
        "envelopeVersion": original.get("envelopeVersion", 1),
        "seq": original["seq"],
        "message": {
            **{key: value for key, value in message.items() if key not in ("messageId", "metadata")},
            "messageId": f"m-{uuid.uuid4().hex}",
            "metadata": metadata,
        },
        "from": original["from"],
        "to": list(original["to"]),
        "sentAt": _iso(now),
        "expiresAt": _iso(now + ttl),
        "turn": dict(original["turn"]),
    }
    return sign(unsigned, identity)


def _retry_envelope(
    state: BridgeState, identity, message_id: str
) -> tuple[int, dict[str, Any] | None, dict[str, Any] | None]:
    """Mint a fresh envelope for a stored attempt and deposit it, without printing.

    Returns (status, result, envelope): the envelope is the NEW one, not the stored attempt.
    The new envelope is recorded in ``sent.jsonl`` before the deposit, like any send — a
    retry is a new attempt in the same thread, and the ledger is what a later retry is
    minted from. The ``knok retry`` command uses this directly so it can format the outcome
    itself; the ``send --retry-of`` path keeps its own printing in ``_retry`` below.
    """
    original = _find_attempt(state, message_id)
    if original is None:
        print(
            f"no attempt {message_id} in {_ledger_path(state)}: a retry repeats an attempt this "
            "agent actually made, and only its own record can say which thread that was",
            file=sys.stderr,
        )
        return 4, None, None
    if original.get("from") != identity.agent_id:
        print(f"{message_id} was sent by {original.get('from')}, not by me", file=sys.stderr)
        return 4, None, None
    try:
        envelope = _mint_retry_envelope(original, identity, datetime.now(timezone.utc))
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        print(f"cannot retry {message_id}: the stored attempt cannot be re-offered ({exc})", file=sys.stderr)
        return 4, None, None
    _remember_attempt(state, envelope)
    status, result = _try_deposit(HubClient(state.hub_url, identity), envelope)
    return status, result, envelope


def _retry(state: BridgeState, identity, args: argparse.Namespace) -> int:
    """Mint a fresh envelope for an earlier attempt, so its thread survives the retry (#48).

    A retry that mints a new ``contextId`` fragments the conversation: the peer answers a thread
    that started at the retry instead of continuing the one the first attempt opened. The new
    envelope keeps the original's context, seq, turn, role and parts, and carries ``retryOf``
    naming the original — a new messageId, not the old one, because the old one is in ``seen``
    and would be dropped.
    """
    status, result, envelope = _retry_envelope(state, identity, args.retry_of)
    if envelope is not None:
        message = envelope["message"]
        print(
            json.dumps(
                {
                    "messageId": message["messageId"],
                    "retryOf": args.retry_of,
                    "contextId": message["contextId"],
                    "retried": True,
                    "delivered": status == 0,
                    **(result or {}),
                    **({"status": status} if status != 0 else {}),
                },
                sort_keys=True,
            )
        )
    else:
        # No attempt to retry: name the id the caller asked for, so the failure is as
        # machine-readable as the success.
        print(
            json.dumps(
                {
                    "messageId": args.retry_of,
                    "retried": True,
                    "delivered": False,
                    "status": status,
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
    delivered: bool = False,
) -> dict[str, Any]:
    """One message's retry decision, in the shape ``knok retry`` prints (and --json emits).

    ``delivered`` is the one field a caller needs to tell the outcomes apart: a retry that
    landed, a message already resolved by an earlier retry, and a message that is terminally
    dead all look the same in the exit code (scan mode exits 0 for all three), so the outcome
    says it. It is True only when a retry was performed and the hub accepted it, or when an
    earlier retry already did.
    """
    outcome: dict[str, Any] = {
        "messageId": notice.get("messageId"),
        "contextId": notice.get("contextId"),
        "kind": notice.get("kind"),
        "rule": notice.get("rule"),
        "decision": decision,
        "reason": reason,
        "attempt": attempt,
        "notBefore": _iso(not_before) if not_before is not None else None,
        "delivered": delivered,
    }
    return outcome


def _retry_line(outcome: dict[str, Any]) -> str:
    """One decision as a line a human can scan."""
    message_id = outcome.get("messageId")
    decision = outcome.get("decision")
    if decision == "retry":
        if "status" not in outcome:
            # No deposit was attempted. A dry run says so; a retry the command could not
            # perform says why not — the two must not read the same.
            if outcome.get("dryRun"):
                return f"would retry {message_id} (attempt {outcome.get('attempt')})"
            return f"could not retry {message_id} (attempt {outcome.get('attempt')}): {outcome.get('reason')}"
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
    if decision == "resolved":
        return f"resolved {message_id}: retried (attempt {outcome.get('attempt')}), delivered"
    return f"terminal {message_id}: {outcome.get('reason')}"


def _retry_record(
    notice: dict[str, Any],
    decision,
    now: datetime,
    status: int | None = None,
    delivered: bool | None = None,
    reserved: bool = False,
    retried_message_id: str | None = None,
) -> dict[str, Any]:
    """One line for ``retries.jsonl``: the decision, and, for a performed retry, its result.

    A performed retry leaves two lines. The reservation is written *before* the deposit and is
    what bounds the retry: a deposit the adapter cannot count must not happen, so when the
    reservation cannot be written the retry does not run. The outcome is written after it, and
    carries the notice it answered (``noticeAt``) so a later scan can tell this failure is
    already fixed — a retry the hub accepted resolves the message, it does not wait to be
    repeated. The outcome also carries ``retriedMessageId``: the new envelope the retry
    deposited. ``messageId`` stays the original id, so a later scan still matches the notice.
    The budget counts the attempt once, not the lines (see ``retry_count``).
    """
    moment = notice_time(notice)
    record: dict[str, Any] = {
        "messageId": notice.get("messageId"),
        "contextId": notice.get("contextId"),
        "kind": notice.get("kind"),
        "rule": notice.get("rule"),
        "attempt": decision.attempt,
        "at": _iso(now),
        "decision": "reserved" if reserved else decision.action,
        "reason": decision.reason,
        "notBefore": _iso(decision.not_before) if decision.not_before is not None else None,
        "noticeAt": _iso(moment) if moment is not None else None,
    }
    if status is not None:
        record["status"] = status
    if delivered is not None:
        record["delivered"] = delivered
    if retried_message_id is not None:
        record["retriedMessageId"] = retried_message_id
    return record


def _reserve_due_retry(directory, notice, decision, now, redecide):
    """Re-read the retry ledger under its lock, re-decide, and reserve the retry (#117).

    Two scans that decided the same retry from the same ledger must not spend one budget
    slot: the lock serialises the re-read and the reservation, so the second scan sees the
    first's reservation and takes the next attempt number — or a terminal decision when the
    budget is spent, or a waiting one when the next attempt is not due yet. ``redecide``
    takes the fresh ledger and returns the decision for this notice; the returned decision
    is the one to deposit, not the stale one from phase one. Returns (decision, outcome),
    where outcome is ``"reserved"`` (deposit it), ``"terminal"`` (record the decision and
    report it), ``"waiting"`` (report it, re-decide on the next scan) or ``"unrecordable"``
    (the ledger could not be read or written, so no deposit happens — fail closed).
    """
    try:
        with retry_ledger_lock(directory):
            fresh = read_retries(directory)
            fresh_decision = redecide(fresh)
            if fresh_decision.action == "terminal":
                return fresh_decision, "terminal"
            if not due(fresh_decision, now):
                return fresh_decision, "waiting"
            reservation = _retry_record(notice, fresh_decision, now, reserved=True)
            if not record_retry(directory, reservation):
                return fresh_decision, "unrecordable"
            return fresh_decision, "reserved"
    except OSError:
        # The lock file could not be opened: the reservation cannot be counted, so the
        # retry does not run — the same fail-closed answer as a ledger write failure.
        return decision, "unrecordable"


#: How bad a performed retry's status is, for the scan exit code. The hub being
#: unreachable (3) is worse than a permanent refusal (2), which is worse than a
#: rate limit (5, transient), which is worse than delivered (0). Numeric order
#: would put 5 first, so the order is explicit, not max(). An unknown status
#: counts as a refusal — a failure the caller cannot place is not a success.
_PERFORMED_SEVERITY = {0: 0, 5: 1, 2: 2, 3: 3}


def cmd_retry(args: argparse.Namespace) -> int:
    """Apply the adapter's retry policy to the failures the bridge recorded (#48).

    ``knok notices`` reports which messages died; this decides which of them are worth
    repeating, and repeats the ones that are due. A retry mints a new envelope for the stored
    attempt (``send --retry-of``) — same thread, same seq, ``retryOf`` naming the original —
    so the thread survives; the policy never mints a fresh ``contextId``. Decisions are
    recorded in ``retries.jsonl`` so the budget is enforced and a decided message is not
    re-decided on every scan; a retry that is not yet due is reported as waiting and
    re-decided on the next scan. A decision about a message the adapter never sent is not
    recorded at all — a missing ledger is an absence, not a decision. A retry the
    hub accepted resolves the failure for that notice, so the next scan reports it resolved
    instead of depositing again.

    The scan runs in two phases. First it decides every message, which needs no hub: a
    terminal decision is recorded even when a retry elsewhere in the scan cannot be performed.
    Then it performs the retries that are due, which needs the identity and the hub. A scan
    that cannot load them still records its terminal decisions and reports the due retries as
    not performed, instead of dying on the first one. Before a due retry is deposited, its
    reservation is written to the ledger under the ledger lock, after a re-read and a
    re-decision against the fresh ledger: the reservation is what bounds the retry, so a retry
    the adapter cannot count is never deposited, and two concurrent scans cannot spend one
    budget slot.

    With ``--message-id`` it decides for one message; without it, it scans every notice.
    ``--send-failed`` is the send-time half: a send that failed, by the messageId the failed
    send printed — there is no notice for it, so the decision comes from ``decide_send``.
    ``--send-failed`` needs ``--send-exit``: the exit code the failed send actually exited
    with. A 2 is a permanent refusal and is never retried; a 3 is retryable; a 5 is a
    rate limit the in-process retries could not clear, retryable after the window. The
    command refuses rather than guessing. With ``--dry-run`` it reports decisions without
    performing retries or recording. With ``--json`` it prints one JSON object per message
    decided; every outcome carries ``delivered`` — True only when a retry landed, or an
    earlier retry already did — because a retry that landed and a message that is terminally
    dead both exit 0 in scan mode. In scan mode the exit code is 0 when the scan completed
    and nothing performed failed, 1 when a due retry could not be performed, and the worst
    performed status (unreachable 3 beats refused 2 beats rate-limited 5) when a performed
    retry failed — so ``knok retry && echo delivered`` does not lie. In single-message mode
    (``--message-id`` or ``--send-failed``) the exit code says what happened to this message:
    0 delivered, 1 deferred (waiting, or a due retry that could not be performed — try again
    later), 2 the retry was performed and the hub refused it, 3 the retry was performed and
    the hub was unreachable, 4 terminal (budget spent, a permanent refusal, expired, dead, an
    unknown id, no stored attempt — no retry was performed and none will be), 5 the retry was
    performed and the hub rate-limited it.
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

    send_failed = getattr(args, "send_failed", None)
    send_exit = getattr(args, "send_exit", None)
    if send_failed is not None and send_exit is None:
        # The exit code is the whole point of the send-time half: a 2 is a permanent
        # refusal and must never be retried, a 3 is retryable. Without it the adapter
        # cannot know which, so the command refuses rather than guessing 3.
        print(
            "retry --send-failed needs --send-exit: pass the exit code the failed send "
            "actually exited with (2 is a permanent refusal, 3 is unreachable)",
            file=sys.stderr,
        )
        if args.json:
            print(
                json.dumps(
                    {
                        "messageId": send_failed,
                        "decision": "unknown",
                        "reason": "no exit code given; pass --send-exit",
                        "attempt": 0,
                        "notBefore": None,
                        "delivered": False,
                    },
                    sort_keys=True,
                )
            )
        return 4
    if send_failed is None and send_exit is not None:
        print("retry --send-exit needs --send-failed", file=sys.stderr)
        return 4
    if send_failed is not None:
        # The send-time half: a send that exited, by the messageId the failed send printed.
        # There is no notice for it — the deposit never happened — so the decision comes from
        # decide_send, and the notice it decides against is synthetic, built from the stored
        # attempt. The synthetic notice is dated from the attempt's sentAt, so a retry the
        # hub accepted resolves it: without a time the resolution guard cannot match, and
        # the same failed send would be deposited again as the next attempt in the ladder.
        envelope = attempts.get(send_failed)
        synthetic: dict[str, Any] = {"messageId": send_failed}
        if isinstance(envelope, dict):
            message = envelope.get("message")
            if isinstance(message, dict) and isinstance(message.get("contextId"), str):
                synthetic["contextId"] = message["contextId"]
            sent_at = envelope_sent_at(envelope)
            if sent_at is not None:
                synthetic["receivedAt"] = _iso(sent_at)
        targets = [(send_failed, synthetic)]
    elif args.message_id:
        notice = latest.get(args.message_id)
        if notice is None:
            print(f"no delivery notice for {args.message_id}", file=sys.stderr)
            if args.json:
                print(
                    json.dumps(
                        {
                            "messageId": args.message_id,
                            "decision": "unknown",
                            "reason": "no delivery notice for this messageId",
                            "attempt": 0,
                            "notBefore": None,
                            "delivered": False,
                        },
                        sort_keys=True,
                    )
                )
            return 4
        targets = [(args.message_id, notice)]
    else:
        targets = sorted(latest.items())

    outcomes: list[dict[str, Any]] = []
    unperformed = False
    performed_status: int | None = None
    # The worst status of any retry this scan performed, by _PERFORMED_SEVERITY. In
    # single-message mode the one performed status is returned directly; in scan mode
    # this is what the exit code reports, so a failed retry is not hidden behind a 0.
    worst_performed: int | None = None
    # Phase one: decide every message. This needs no hub, so a terminal decision is recorded
    # even when a retry elsewhere in the scan cannot be performed.
    due_list: list[tuple[str, dict[str, Any], Any]] = []
    for message_id, notice in targets:
        # A message already decided terminal for *this notice* stays decided; the decision
        # is stable, so re-deciding it on every scan is noise. Terminal is per notice, not
        # per message: a terminal decision for an old notice must not mask a newer notice
        # for the same message (#118).
        decided = terminal_record(retries, message_id, notice_time(notice))
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
        # A retry the hub accepted resolves the failure for this notice: the message is
        # delivered, not waiting to be repeated. A newer notice is a new failure and is
        # decided fresh below.
        resolved = resolved_record(retries, message_id, notice_time(notice))
        if resolved is not None:
            outcomes.append(
                _retry_outcome(
                    notice,
                    "resolved",
                    f"already retried (attempt {resolved.get('attempt')}); the hub accepted the retry",
                    int(resolved.get("attempt") or 0),
                    None,
                    delivered=True,
                )
            )
            continue
        envelope = attempts.get(message_id)
        if send_failed is not None:
            decision = decide_send(send_exit, envelope, retries, now)
        else:
            decision = decide_notice(notice, envelope, retries, now)
        if decision.action == "terminal":
            outcomes.append(_retry_outcome(notice, "terminal", decision.reason, 0, None))
            if not args.dry_run and decision.record:
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
            outcome = _retry_outcome(
                notice, "retry", decision.reason, decision.attempt, decision.not_before
            )
            outcome["dryRun"] = True
            outcomes.append(outcome)
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
                        notice,
                        "retry",
                        f"cannot retry: {exc}",
                        decision.attempt,
                        decision.not_before,
                    )
                )
            unperformed = True
        else:
            for message_id, notice, decision in due_list:
                envelope = attempts.get(message_id)

                def redecide(fresh, _notice=notice, _envelope=envelope):
                    if send_failed is not None:
                        return decide_send(send_exit, _envelope, fresh, now)
                    return decide_notice(_notice, _envelope, fresh, now)

                # Reserve the retry under the ledger lock, against a fresh ledger: the
                # reservation is what bounds it, and the re-decision is what keeps two
                # concurrent scans from spending one budget slot (#117). A retry the adapter
                # cannot count is never deposited — otherwise a ledger that cannot be written
                # turns into an unbounded retry, one deposit per scan.
                decision, reserved = _reserve_due_retry(
                    directory, notice, decision, now, redecide
                )
                if reserved == "terminal":
                    outcomes.append(_retry_outcome(notice, "terminal", decision.reason, 0, None))
                    if not args.dry_run and decision.record:
                        record = _retry_record(notice, decision, now)
                        if record_retry(directory, record):
                            retries.append(record)
                    continue
                if reserved == "waiting":
                    outcomes.append(
                        _retry_outcome(
                            notice,
                            "waiting",
                            decision.reason,
                            decision.attempt,
                            decision.not_before,
                        )
                    )
                    continue
                if reserved == "unrecordable":
                    outcomes.append(
                        _retry_outcome(
                            notice,
                            "retry",
                            "the retry could not be counted (the ledger write failed), so it was not deposited",
                            decision.attempt,
                            decision.not_before,
                        )
                    )
                    unperformed = True
                    continue
                status, result, new_envelope = _retry_envelope(state, identity, message_id)
                if worst_performed is None or _PERFORMED_SEVERITY.get(
                    status, 2
                ) > _PERFORMED_SEVERITY.get(worst_performed, 2):
                    worst_performed = status
                outcome = _retry_outcome(
                    notice,
                    "retry",
                    decision.reason,
                    decision.attempt,
                    decision.not_before,
                    delivered=(status == 0),
                )
                outcome["status"] = status
                retried_message_id = None
                if new_envelope is not None:
                    retried_message_id = new_envelope["message"]["messageId"]
                    outcome["retriedMessageId"] = retried_message_id
                if result is not None:
                    outcome["result"] = result
                outcomes.append(outcome)
                # The outcome is recorded after the deposit. If this write fails, the
                # reservation above still bounds the retry — the next scan counts the
                # attempt and will not deposit it again without a fresh decision. The
                # outcome keeps messageId as the original id (so resolved_record still
                # matches the notice) and names the new envelope it deposited.
                outcome_record = _retry_record(
                    notice,
                    decision,
                    now,
                    status=status,
                    delivered=(status == 0),
                    retried_message_id=retried_message_id,
                )
                if record_retry(directory, outcome_record):
                    retries.append(outcome_record)
                if send_failed is not None or args.message_id:
                    performed_status = status

    for outcome in outcomes:
        if args.json:
            print(json.dumps(outcome, sort_keys=True))
        else:
            print(_retry_line(outcome))
    if performed_status is not None:
        # A retry was performed: the exit code is the deposit's own (0 accepted, 2 the hub
        # refused the retry, 3 the hub was unreachable).
        return performed_status
    if args.dry_run:
        # A dry run is a report, not an action: it never fails.
        return 0
    if send_failed is not None or args.message_id:
        # Single-message mode: the exit code says what happened to this message, so a
        # caller that never reads --json can still tell a delivered retry from a terminal
        # one from one that is still waiting. 0 delivered, 1 deferred (waiting, or a due
        # retry that could not be performed — try again later), 4 terminal (budget spent,
        # a permanent refusal, expired, dead, an unknown id, no stored attempt — no retry
        # was performed and none will be).
        decisions = {outcome.get("decision") for outcome in outcomes}
        if "terminal" in decisions or "unknown" in decisions:
            return 4
        if "waiting" in decisions or unperformed:
            return 1
        return 0
    if worst_performed is not None and worst_performed != 0:
        # A performed retry failed: the exit code is the worst of them, so a scan that
        # performed a failing retry does not exit 0. Unreachable (3) beats refused (2)
        # beats rate-limited (5); a scan that only delivered exits 0 below.
        return worst_performed
    return 1 if unperformed else 0


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
    #: Mint a new envelope for an attempt this agent already made, in its original thread
    #: (#48). The caller that knows which attempt failed is the adapter, so the flag takes
    #: the messageId the failed attempt printed rather than making the caller guess a
    #: context id.
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
    #: mints a new envelope for the stored attempt, so the thread survives; the policy never
    #: mints a fresh contextId. Without --message-id it scans every notice; with --dry-run it
    #: reports decisions without performing retries or recording.
    retry = sub.add_parser("retry", help="retry the failures the bridge recorded, when the policy says to")
    send_failed_group = retry.add_mutually_exclusive_group()
    send_failed_group.add_argument("--message-id", default=None, metavar="MESSAGE_ID")
    #: The send-time half of #48: a send that failed, by the messageId the failed send printed.
    #: There is no notice for it — the deposit never happened — so the decision comes from
    #: decide_send, not from a notice. --send-exit is the exit code the failed send actually
    #: exited with (2 is a permanent refusal and is never retried, 3 is retryable, 5 is a
    #: rate limit the in-process retries could not clear and is retryable after the window);
    #: it is required with --send-failed, because guessing 3 would retry a permanently
    #: refused send, and guessing 2 would lose a rate-limited one.
    send_failed_group.add_argument("--send-failed", default=None, metavar="MESSAGE_ID")
    retry.add_argument(
        "--send-exit",
        type=int,
        default=None,
        metavar="CODE",
        help="the exit code the failed send exited with (required with --send-failed)",
    )
    retry.add_argument("--dry-run", action="store_true")
    retry.add_argument("--json", action="store_true")
    retry.set_defaults(func=cmd_retry)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
