"""The adapter's retry policy: when a failed message is worth repeating (#48).

The wire half (#56) gives the adapter a way to repeat an attempt — ``send --retry-of``
re-deposits the stored envelope verbatim, so the thread survives — and the read half (#64)
gives it the fact it needs to decide — ``knok notices`` reports which ``messageId`` died, and
under which rule. What neither gives it is the decision: *when* is a repeat worth it, and how
often? That is the adapter's policy, and it lives here, not in the CLI's send path and not in
the bridge: the bridge records the failure, the CLI reports it, and only the caller knows
whether the message is still worth sending.

Two failure domains, two answers.

A send that never reached the hub (``send`` exits 3, unreachable) is a transport failure: the
envelope is still valid, the deposit may not have happened, and a replay is idempotent — the
hub dedupes by ``messageId`` and answers "duplicate" when the first copy landed. So the
adapter retries it, bounded, with a short backoff. A send the hub permanently refused (exit 2:
unknown sender or recipient, a bad signature, a reused ``messageId``) is not retried: the same
envelope fails identically. (A 429 over-capacity refusal is already retried in-process by
``_try_deposit``; exit 2 means it exhausted that, or was never retryable.)

A message that died *after* the hub accepted it — the kind ``knok notices`` reports — is
decided by its kind, because a verbatim replay only helps when the failure was transient and
the envelope is still valid:

===========  ========  ========  ==============================================
kind         rule      decision  why
===========  ========  ========  ==============================================
refused      limits    RETRY     A rate limit is transient: the hourly window
                                 clears at the next hour, the daily window at
                                 midnight. A replay after the window passes
                                 should succeed.
refused      policy    TERMINAL  A gate policy decision. The adapter cannot
                                 know whether the policy changed, so it must
                                 not second-guess the gate. The operator may
                                 re-send explicitly.
refused      thread    TERMINAL  A thread rule (a closed thread, or no reply
                                 owed). The thread state does not change by
                                 waiting; a replay hits the same rule.
refused      malformed TERMINAL  The message itself is broken; a verbatim
                                 replay fails identically.
refused      blocked   TERMINAL  Blocked senders get no notice at all (§9),
                                 so this should never appear; if it does,
                                 never retry.
refused      (other)   TERMINAL  An unknown refusal rule; do not guess.
expired      —         TERMINAL  The envelope is past its TTL. A verbatim
                                 replay is accepted by the hub (202) but
                                 immediately dropped with another expired
                                 frame, so it buys nothing. A re-offer — a
                                 new envelope, a fresh TTL, the same
                                 context, a ``retryOf`` marker — is a
                                 separate explicit action, not a replay.
dead         —         TERMINAL  The spec forbids it: "A dead letter is never
                                 retried automatically, and never silently."
                                 The ``messageId`` is in ``seen``, so a
                                 replay would be dropped by dedupe anyway.
                                 An explicit owner re-offer is the remedy.
gap / late   —         NO        These are about inbound streams — messages
                                 sent *to* us that are missing or late. They
                                 name seqs, not our messageIds. The remedy
                                 is a RESEND request, not a send retry.
===========  ========  ========  ==============================================

Three bounds, and they are the whole policy:

* **At most two retries per message** (``MAX_RETRIES``) — the original send plus two retries
  is three attempts, matching the in-process deposit bound. A retry that keeps failing is a
  message the other side does not want, or a network that is not coming back; either way the
  adapter stops.
* **Backoff by failure kind.** A rate-limit retry is due one hour after the notice (the hourly
  window), and the second a day after it (the daily window) — the notice carries only the rule,
  not which window fired, so the ladder covers both. An unreachable-send retry is due one
  minute, then five minutes, after the attempt — the spec's poison ladder start. A retry that
  is not yet due is "waiting", not "failed": the next scan re-decides it.
* **TTL.** A retry is only valid while the original envelope has not expired. The policy reads
  the envelope's ``expiresAt`` from ``sent.jsonl``; if there is no stored attempt to replay,
  or the envelope expires before the retry is due, the decision is terminal. A retry must
  never mint a fresh ``contextId`` — it replays the stored envelope, so the thread survives —
  and it must never be attempted on an envelope that cannot arrive.

How a caller tells the outcomes apart (criterion 4). A retry that landed, a message that is
terminally dead, a message that is still waiting and an unknown id must not all look the same.
Every ``knok retry`` outcome carries ``delivered`` — True only when a retry landed or an
earlier retry already did — and in single-message mode (``--message-id`` or ``--send-failed``)
the exit code says the same thing without --json: 0 delivered, 1 deferred (waiting, or a due
retry that could not be performed — try again later), 2 the retry was performed and the hub
refused it, 3 the retry was performed and the hub was unreachable, 4 terminal (budget spent,
a permanent refusal, expired, dead, an unknown id, no stored attempt — no retry was performed
and none will be). In scan mode the exit code is 0 when the scan completed and 1 when a due
retry could not be performed; the per-message outcomes in --json carry the detail there. The
reason text says which terminal bound stopped it; the exit code only says that it stopped.

How attempts are recorded. ``sent.jsonl`` already records every attempt (``messageId``,
``contextId``, the signed envelope) before deposit, so a retry is a replay of a record, not a
rebuild. This module adds ``retries.jsonl``: one fsynced line per retry the adapter *performs*
and per terminal decision it records, so the budget is enforced and a decided message is not
re-decided on every scan. A "waiting" decision is not recorded — the next scan re-decides it,
which is cheap and deterministic. Three rules keep the ledger honest:

* A decision about a message the adapter never sent is not recorded at all: a missing ledger
  is an absence, not a decision, so "no stored attempt to replay" stays unrecorded and the
  next scan re-decides it.
* A retry is reserved before it is deposited: the reservation is what bounds it, so a retry
  the adapter cannot count is never deposited. A performed retry leaves two lines — the
  reservation and the outcome — and the budget counts the attempt once, not the lines.
* A retry the hub accepted resolves the failure for that notice: the outcome line carries the
  notice it answered, so a later scan reports the message resolved instead of depositing the
  same envelope again. A newer notice is a new failure and gets its own retries within the
  budget.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .bridge import NOTICES

#: At most two retries per message: the original send plus two retries is three attempts,
#: matching the in-process deposit bound (``_try_deposit``). A message that keeps failing is
#: either unwanted or unreachable; either way the adapter stops.
MAX_RETRIES = 2

#: Every attempt this agent deposited, with the signed envelope it deposited. ``--retry-of``
#: reads it: only the sender knows which attempt it is repeating, so the sender has to keep
#: the record. The CLI writes this file; the policy reads it to find the envelope a retry
#: would replay, and to check the envelope has not expired.
SENT_LEDGER = "sent.jsonl"

#: One fsynced line per retry performed and per terminal decision recorded, in the state
#: directory next to ``sent.jsonl`` and ``notices.jsonl``.
RETRY_LEDGER = "retries.jsonl"

#: Backoff for a ``refused``/``limits`` notice, by retry number (attempt 1, then attempt 2).
#: The notice carries only the rule, not which window fired, so the ladder covers both: the
#: hourly window clears within an hour, the daily window within a day.
BACKOFF_LIMITS = (timedelta(hours=1), timedelta(days=1))

#: Backoff for a send that failed because the hub was unreachable (exit 3), by retry number.
#: The spec's poison-ladder start: the hub is a transport failure, not a gate decision, so the
#: retry is due in minutes, not hours.
BACKOFF_UNREACHABLE = (timedelta(minutes=1), timedelta(minutes=5))

#: Each notice kind dates itself with its own word. The policy needs the notice's time to date
#: the backoff from; a notice with no parseable time is dated from now instead.
NOTICE_TIMES = ("receivedAt", "expiredAt", "deadedAt", "detectedAt", "releasedAt", "at")

#: The one refusal rule a replay can outlast. Every other rule is a decision about this
#: message, not about this moment.
RETRYABLE_RULE = "limits"


@dataclass(frozen=True)
class Decision:
    """One answer from the policy: retry, or do not — and, for a retry, when it is due.

    ``action`` is ``"retry"`` or ``"terminal"``. ``reason`` is the one sentence the operator
    (or the adapter's log) gets. ``not_before`` is when a retry is due; ``attempt`` is which
    retry number this would be (1 or 2). Both are None on a terminal decision. ``record`` says
    whether the caller should record the decision: a decision about a message the adapter never
    sent is an absence, not a decision, so it is never recorded.
    """

    action: str
    reason: str
    not_before: datetime | None = None
    attempt: int = 0
    record: bool = True


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def notice_time(notice: dict[str, Any]) -> datetime | None:
    """When the notice says the failure happened, or None when it does not say."""
    for key in NOTICE_TIMES:
        parsed = _parse_iso(notice.get(key))
        if parsed is not None:
            return parsed
    return None


def envelope_expires_at(envelope: dict[str, Any] | None) -> datetime | None:
    """The stored envelope's ``expiresAt``, or None when there is none to read."""
    if not isinstance(envelope, dict):
        return None
    return _parse_iso(envelope.get("expiresAt"))


def envelope_sent_at(envelope: dict[str, Any] | None) -> datetime | None:
    """The stored envelope's ``sentAt``, or None when there is none to read."""
    if not isinstance(envelope, dict):
        return None
    return _parse_iso(envelope.get("sentAt"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """The dict records in a jsonl file, skipping blank and unreadable lines.

    A torn line (a crash mid-append, or a byte that is not valid UTF-8) loses only
    that line: each line is decoded on its own, so one bad byte does not take the
    whole ledger with it. A file that cannot be opened at all (permissions, a
    missing directory) reads as empty, and the caller is told — the scan proceeds
    instead of dying on bookkeeping. A record the adapter cannot read is a record
    it cannot count, so a retry it cannot count is never deposited (the reservation
    in ``cmd_retry`` fails closed on the same ledger).
    """
    if not path.exists():
        return []
    try:
        handle = open(path, "rb")
    except OSError as exc:
        print(f"warning: could not read {path}: {exc}", file=sys.stderr)
        return []
    records: list[dict[str, Any]] = []
    with handle:
        for raw in handle:
            line = raw.decode("utf-8", errors="replace")
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def read_notices(directory: str | Path) -> list[dict[str, Any]]:
    """Every notice the bridge recorded, in file order."""
    return _read_jsonl(Path(directory) / NOTICES)


def read_attempts(directory: str | Path) -> dict[str, dict[str, Any]]:
    """The last stored envelope per ``messageId`` this agent sent.

    ``sent.jsonl`` records every attempt before deposit; a message that was retried is in
    there once per deposit, and the last record is the one a replay would repeat.
    """
    attempts: dict[str, dict[str, Any]] = {}
    for record in _read_jsonl(Path(directory) / SENT_LEDGER):
        envelope = record.get("envelope")
        if not isinstance(envelope, dict):
            continue
        message = envelope.get("message")
        if not isinstance(message, dict):
            continue
        message_id = message.get("messageId")
        if isinstance(message_id, str) and message_id:
            attempts[message_id] = envelope
    return attempts


def read_retries(directory: str | Path) -> list[dict[str, Any]]:
    """Every retry decision this adapter recorded, in file order."""
    return _read_jsonl(Path(directory) / RETRY_LEDGER)


def retry_count(retries: list[dict[str, Any]], message_id: str) -> int:
    """How many retries this adapter already performed for ``message_id``.

    Counted by attempt number, not by record: a retry leaves a reservation and an outcome
    record for the same attempt, and the two together are one retry, not two. A record with no
    attempt number counts once, so a hand-edited ledger still bounds.
    """
    attempts = {
        record.get("attempt")
        for record in retries
        if record.get("messageId") == message_id
        and record.get("decision") in ("retry", "reserved")
        and record.get("attempt") is not None
    }
    unnumbered = any(
        record.get("messageId") == message_id
        and record.get("decision") in ("retry", "reserved")
        and record.get("attempt") is None
        for record in retries
    )
    return len(attempts) + (1 if unnumbered else 0)


def terminal_decided(retries: list[dict[str, Any]], message_id: str) -> bool:
    """Whether a terminal decision for ``message_id`` is already on record."""
    return terminal_record(retries, message_id) is not None


def terminal_record(
    retries: list[dict[str, Any]], message_id: str
) -> dict[str, Any] | None:
    """The latest terminal decision recorded for ``message_id``, or None."""
    found: dict[str, Any] | None = None
    for record in retries:
        if record.get("messageId") == message_id and record.get("decision") == "terminal":
            found = record
    return found


def resolved_record(
    retries: list[dict[str, Any]], message_id: str, notice_at: datetime | None
) -> dict[str, Any] | None:
    """The retry outcome that already delivered for this notice, or None.

    Resolution is per notice, not per message: the same message can fail again (a newer
    notice), and that failure gets its own retries within the budget. ``notice_at`` is the
    notice's own time, as ``notice_time`` reads it; a notice with no time cannot be matched,
    so it is never reported resolved.
    """
    if notice_at is None:
        return None
    stamp = _iso(notice_at)
    for record in reversed(retries):
        if (
            record.get("messageId") == message_id
            and record.get("decision") == "retry"
            and record.get("status") == 0
            and record.get("noticeAt") == stamp
        ):
            return record
    return None


def record_retry(directory: str | Path, record: dict[str, Any]) -> bool:
    """Append one fsynced retry record. False (and loud) when it cannot be written.

    A record the adapter cannot write is a retry it cannot count, so the caller is told: the
    decision stands, but the budget is not enforced for it.
    """
    path = Path(directory) / RETRY_LEDGER
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return True
    except OSError as exc:
        print(f"warning: could not record the retry in {path}: {exc}", file=sys.stderr)
        return False


def _terminal(reason: str, record: bool = True) -> Decision:
    return Decision(action="terminal", reason=reason, record=record)


def _retryable(
    message_id: str,
    envelope: dict[str, Any] | None,
    retries: list[dict[str, Any]],
    base: datetime,
    backoff: tuple[timedelta, ...],
    why: str,
    now: datetime,
) -> Decision:
    """The shared tail of every retryable decision: budget, backoff, TTL.

    ``base`` is the moment the backoff is dated from (the notice's time, or the attempt's
    ``sentAt``); ``backoff`` is the ladder for this failure kind. Returns a retry decision when
    the budget allows and the envelope outlives the due time, else a terminal one saying which
    bound stopped it.
    """
    if envelope is None:
        # Not a decision about this message — the ledger holds no attempt to replay — so it
        # is never recorded: a missing ledger is an absence, and recording it would claim a
        # decision the adapter never made.
        return _terminal(
            "no stored attempt to replay; nothing in sent.jsonl carries this id", record=False
        )
    done = retry_count(retries, message_id)
    if done >= MAX_RETRIES:
        return _terminal(
            f"retry budget exhausted: {done} retr{'y' if done == 1 else 'ies'} already, "
            f"at most {MAX_RETRIES}"
        )
    attempt = done + 1
    not_before = base + backoff[attempt - 1]
    expires = envelope_expires_at(envelope)
    if expires is not None and expires <= now:
        return _terminal("the envelope already expired; a replay would be dropped at once")
    if expires is not None and expires <= not_before:
        return _terminal(
            "the envelope expires before the retry is due; a replay would be dropped at once"
        )
    return Decision(
        action="retry",
        reason=why,
        not_before=not_before,
        attempt=attempt,
    )


def decide_notice(
    notice: dict[str, Any],
    envelope: dict[str, Any] | None,
    retries: list[dict[str, Any]],
    now: datetime | None = None,
) -> Decision:
    """Decide what the adapter does about one notice from ``notices.jsonl``.

    ``envelope`` is the stored attempt from ``sent.jsonl`` (None when this agent never sent
    that id); ``retries`` is the retry ledger so far; ``now`` defaults to the current time.
    The decision is pure: it reads nothing from disk and writes nothing.
    """
    moment = now or datetime.now(timezone.utc)
    kind = notice.get("kind")
    if kind in ("gap", "late"):
        # A gap or a late notice names no single message — a gap names seqs, a late notice
        # names a message that is late, not one that failed — so there is nothing to pass to
        # --retry-of, and the remedy is a RESEND request, not a send retry.
        return _terminal(
            f"a {kind} notice is about an inbound stream, not a message this agent sent; the "
            "remedy is a RESEND request, not a send retry"
        )
    message_id = notice.get("messageId")
    if not isinstance(message_id, str) or not message_id:
        return _terminal("the notice names no messageId, so there is nothing to pass to --retry-of")
    if kind == "refused":
        rule = notice.get("rule")
        if rule == RETRYABLE_RULE:
            base = notice_time(notice) or moment
            return _retryable(
                message_id,
                envelope,
                retries,
                base,
                BACKOFF_LIMITS,
                "a rate limit is transient; the window clears, so a replay after it should succeed",
                moment,
            )
        if rule == "policy":
            return _terminal(
                "the peer's gate refused this on policy; the adapter cannot know whether the "
                "policy changed, so it must not second-guess the gate"
            )
        if rule == "thread":
            return _terminal(
                "the peer's gate refused this on a thread rule; the thread state does not change "
                "by waiting, so a replay hits the same rule"
            )
        if rule == "malformed":
            return _terminal(
                "the peer's gate refused this as malformed; the message itself is broken, so a "
                "verbatim replay fails identically"
            )
        if rule == "blocked":
            return _terminal(
                "a blocked sender gets no notice at all, so this rule should never appear; "
                "if it does, never retry"
            )
        return _terminal(f"unknown refusal rule {rule!r}; do not guess")
    if kind == "expired":
        return _terminal(
            "the envelope is past its TTL; a verbatim replay is accepted by the hub but "
            "immediately dropped with another expired frame, so it buys nothing — a re-offer is "
            "a separate explicit action, not a replay"
        )
    if kind == "dead":
        return _terminal(
            "a dead letter is never retried automatically, and the messageId is in seen, so a "
            "replay would be dropped by dedupe — an explicit owner re-offer is the remedy"
        )
    return _terminal(f"unknown notice kind {kind!r}; do not guess")


def decide_send(
    exit_code: int,
    envelope: dict[str, Any] | None,
    retries: list[dict[str, Any]],
    now: datetime | None = None,
) -> Decision:
    """Decide what the adapter does about a ``send`` result, by its exit code.

    This is the send-time half of the policy: a deposit that never happened (exit 3) is worth
    repeating, a deposit the hub permanently refused (exit 2) is not. The adapter calls it
    after a failed send, with the envelope it tried to deposit (from ``sent.jsonl``) and the
    retry ledger so far. Exit 0 is not a failure and needs no retry.
    """
    moment = now or datetime.now(timezone.utc)
    if exit_code == 0:
        return _terminal("the send was accepted; nothing to retry")
    if exit_code == 2:
        return _terminal(
            "the hub permanently refused the deposit — an unknown sender or recipient, a bad "
            "signature, a reused messageId — so the same envelope fails identically"
        )
    if exit_code == 3:
        message_id = None
        if isinstance(envelope, dict):
            message = envelope.get("message")
            if isinstance(message, dict):
                message_id = message.get("messageId")
        if not isinstance(message_id, str) or not message_id:
            return _terminal("no messageId to retry; the attempt was never recorded", record=False)
        base = envelope_sent_at(envelope) or moment
        return _retryable(
            message_id,
            envelope,
            retries,
            base,
            BACKOFF_UNREACHABLE,
            "the hub was unreachable, so the deposit may not have happened; a replay is "
            "idempotent, the hub dedupes by messageId",
            moment,
        )
    if exit_code == 4:
        return _terminal("no attempt found under that id; there is nothing to repeat")
    return _terminal(f"unknown send result {exit_code}; do not guess")


def due(decision: Decision, now: datetime | None = None) -> bool:
    """Whether a retry decision is due now (a terminal decision is never due).

    A retry with no ``not_before`` has no waiting period, so it is due at once.
    """
    if decision.action != "retry":
        return False
    if decision.not_before is None:
        return True
    return (now or datetime.now(timezone.utc)) >= decision.not_before
