"""A durable queue under the envelope layer (SPEC §6, issue #7).

The queue is the bridge's memory of what it owes a recipient: an envelope is
durable the moment :meth:`Queue.put` returns, and the sender's copy may only
be dropped once the recipient's bridge has acked. Everything below exists to
make that promise survive a crash:

* **Storage is SQLite from the stdlib, nothing else.** WAL mode,
  ``synchronous=FULL`` — a ``put`` returns only after its commit has been
  fsynced to the WAL, so a message that was accepted is still there after
  ``os._exit(1)`` or a power cut. One connection, guarded by one lock; a
  second connection in the same process would only buy lock contention and
  a second chance to interleave writes.
* **One process owns the queue.** Opening takes an advisory ``flock`` on a
  ``<path>.lock`` file; a second opener gets :class:`QueueLockedError`.
  This is the same failure the Phase 0 poller had — two writers clobbering
  each other's state — and §6's delivery rules assume a single owner.
* **Dedupe is durable, not in-memory.** Every accepted ``messageId`` is
  recorded in a ``seen`` table that survives ack, expiry, dead-lettering
  and restart, so a re-put is dropped as a duplicate forever, never
  delivered twice.
* **Ordering is per (contextId, sender→recipient), by ``seq``.** ``seq``
  starts at 0 and increments by 1 per message. A gap holds later messages;
  :meth:`Queue.resend` reports what is missing; after the context TTL the
  held messages are released in order with a gap notice. A ``seq`` below
  the last delivered is a duplicate *unless* a gap release skipped it, in
  which case it is a late arrival: delivered out of order with a ``late``
  notice, never dropped silently (issue #19). One ``seq`` holds one
  message: a second id reusing a ``seq`` that is still held is a duplicate
  too (issue #111) — accepting it would strand it once the first is acked.
* **The queue knows whose mail it is.** ``Queue(path, agent_id)`` is
  bound at open to one owner, validated with
  ``knok.identity.validate_agent_id``. ``put`` refuses an envelope not
  addressed to the owner, and refuses a multi-recipient envelope outright:
  fan-out is the hub's job, and silently keying a two-recipient message to
  its first addressee would deliver it nowhere else. ``get`` returns the
  envelope unchanged — it never rewrites ``to``.
* **The local queue is capped.** ``put`` refuses past 10,000 envelopes or
  256 MiB per agent — HUB.md's mailbox numbers, applied locally (issue
  #116) — because the hub copy is deleted on ack and an undrained local
  queue would otherwise grow without limit. A refusal raises
  :class:`QueueFullError`, a ``ValueError`` the bridge already treats as
  "leave it at the hub"; a duplicate is still answered ``"duplicate"`` at
  cap. :meth:`Queue.usage` reports the count and the bytes.
* **Poison messages dead-letter.** Five delivery attempts with backoff
  (1m, 5m, 30m, 2h, 12h), then the message moves to a dead-letter store
  visible to the owner via :meth:`Queue.dead_letter`. Nothing retries
  forever.
* **Expiry emits a transport frame, not a Message.** :meth:`Queue.expire`
  drops messages past ``expiresAt`` and returns the ``{"kind": "expired",
  ...}`` frame §6 specifies — unsigned, not signed as the recipient, never
  entering a thread.
* **Notices are queued, delivered once.** A ``late`` arrival and a ``dead``
  letter each produce one transport frame, handed out by :meth:`Queue.get`
  alongside the gap frame, so the sender learns its message died rather
  than waiting for a reply that cannot come. One live notice is stored per
  event, and notices interleave with messages — a backlog delays a due
  message by at most one notice, never starves it (issue #115).
* **``seen`` is pruned, not grown forever.** Rows older than the 30-day
  ``expiresAt`` bound are deleted by :meth:`Queue.expire`, except those
  whose message is still live (issue #13).
* **Restart replays unacked, never re-delivers acked.** Rows handed out but
  unacked at crash return to the queue on open; acked rows are gone from
  the live table and their ids stay in ``seen``.

What this deliberately does **not** do: verify envelope signatures (the
envelope layer does that before ``put`` — the queue stores what it is
given); accept sealed (form 2) envelopes — their ``messageId`` is in clear,
but their ``contextId`` is inside ``sealed``, so the queue cannot compute
the stream key or order them before decryption, and it refuses them loudly
instead of guessing; deliver to the agent (delivery is the bridge's job —
``get`` hands the bridge the next envelope).
"""

from __future__ import annotations

import fcntl
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import envelope as _envelope
from .identity import validate_agent_id

__all__ = ["Queue", "QueueLockedError", "QueueFullError", "BACKOFF_SECONDS",
           "DEFAULT_CONTEXT_TTL", "SEEN_RETENTION", "MAX_QUEUE_MESSAGES",
           "MAX_QUEUE_BYTES"]

#: Delivery attempts, then dead-letter (§6). Backoff between attempts.
BACKOFF_SECONDS = (60, 300, 1800, 7200, 43200)
MAX_ATTEMPTS = len(BACKOFF_SECONDS)
#: How long a gap may hold messages before they are released in order with
#: a gap notice (§6). The spec names a "context TTL" without a number; the
#: default matches the default message TTL (72h, §6 expiry).
DEFAULT_CONTEXT_TTL = timedelta(hours=72)
#: How long a ``messageId`` stays in ``seen`` (§6 allows ``expiresAt`` up to 30 days out, so a
#: duplicate may legitimately arrive that late). Pruning is bounded by this and the context TTL.
SEEN_RETENTION = timedelta(days=30)
#: How long a notice taken by the bridge but not confirmed waits before being offered again. The
#: bridge confirms only after the frame is fsynced into its own log, so a crash in between must
#: not lose it — and the retry must be long enough not to spin inside one drain loop.
NOTICE_BACKOFF_SECONDS = 60
#: The local queue is bounded by the same numbers as the hub mailbox (HUB.md, "Mailbox cap"):
#: 10,000 envelopes or 256 MiB per agent, whichever comes first (issue #116). The hub cap alone
#: does not bound the recipient: once the bridge acks the hub the hub copy is gone and its
#: capacity is freed, so an undrained local queue would grow without limit. ``put`` refuses past
#: these bounds instead of storing.
MAX_QUEUE_MESSAGES = 10_000
MAX_QUEUE_BYTES = 256 * 1024 * 1024

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    message_id      TEXT PRIMARY KEY,
    context_id      TEXT NOT NULL,
    sender          TEXT NOT NULL,
    recipient       TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    envelope_json   TEXT NOT NULL,
    expires_at      REAL NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('queued', 'delivering')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    available_at    REAL NOT NULL,
    inserted_at     REAL NOT NULL,
    late            INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_messages_stream
    ON messages (context_id, sender, recipient, seq);
CREATE TABLE IF NOT EXISTS seen (
    message_id  TEXT PRIMARY KEY,
    context_id  TEXT NOT NULL,
    first_seen  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS streams (
    context_id  TEXT NOT NULL,
    sender      TEXT NOT NULL,
    recipient   TEXT NOT NULL,
    next_seq    INTEGER NOT NULL DEFAULT 0,
    gap_since   REAL,
    PRIMARY KEY (context_id, sender, recipient)
);
CREATE TABLE IF NOT EXISTS notices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL,
    payload      TEXT NOT NULL,
    created_at   REAL NOT NULL,
    -- pending -> taken -> delivered. "taken" is handed to the bridge but not yet on disk
    -- anywhere else; it is re-offered after NOTICE_BACKOFF_SECONDS so a crash or a failed
    -- write cannot swallow the frame the sender depends on.
    state        TEXT NOT NULL CHECK (state IN ('pending', 'taken', 'delivered')),
    available_at REAL NOT NULL,
    -- Stable identity of the event this notice reports, for dedupe (issue #115). A second
    -- notice for the same live event is not stored twice; a delivered one does not block
    -- a later notice for the same event. Rows written before this column existed carry
    -- '' and are never matched by a real key.
    dedupe_key   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS skipped (
    context_id  TEXT NOT NULL,
    sender      TEXT NOT NULL,
    recipient   TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    released_at REAL NOT NULL,
    PRIMARY KEY (context_id, sender, recipient, seq)
);
CREATE TABLE IF NOT EXISTS dead_letters (
    message_id  TEXT PRIMARY KEY,
    context_id  TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    attempts    INTEGER NOT NULL,
    dead_at     REAL NOT NULL,
    reason      TEXT NOT NULL
);
"""


def _retries_a_seen_message(message: dict, conn) -> bool:
    """Whether this envelope is a retry of a message this queue has already seen.

    A retry mints a new id carrying ``metadata.retryOf`` naming the original (SPEC §8). It
    arrives at the *same* seq as the original, so a spent seq alone cannot tell a retry from a
    collision — the name can. No retryOf, and the id it would retry was never seen: not a retry.
    """
    if not isinstance(message, dict):
        return False
    metadata = message.get("metadata")
    if not isinstance(metadata, dict):
        return False
    original = metadata.get("retryOf")
    # The claim is enough. A sender that lies here only silences its own message, and requiring
    # the original to still be in ``seen`` would fail exactly when the ledger has been pruned.
    return isinstance(original, str) and bool(original)


class QueueLockedError(RuntimeError):
    """A second process tried to open a queue that is already owned."""


class QueueFullError(ValueError):
    """``put`` refused a message: the local queue is at its cap.

    A ``ValueError`` on purpose: the bridge already catches ``ValueError``
    from ``put`` and leaves the item unacked at the hub, so a refused message
    is re-offered instead of acked away (issue #116).
    """


def _parse_iso(value: str) -> datetime:
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts(moment: datetime) -> float:
    return moment.timestamp()


def _notice_dedupe_key(notice: dict[str, Any]) -> str:
    """Stable identity of the event a notice reports (issue #115).

    The key names the event, not the frame: timestamps (``detectedAt``,
    ``releasedAt``) differ between offers of the same event, so the payload
    itself can never be the key. A ``late``/``dead`` notice is one per
    message; a ``gap`` notice is one per released gap. An unknown kind falls
    back to the exact payload, so it dedupes only on an identical re-offer.
    """
    kind = notice.get("kind")
    if kind == "late":
        return f"late:{notice.get('messageId')}"
    if kind == "dead":
        return f"dead:{notice.get('messageId')}"
    if kind == "gap":
        missing = ",".join(str(seq) for seq in notice.get("missing", []))
        return (
            f"gap:{notice.get('contextId')}:{notice.get('from')}"
            f":{notice.get('to')}:{missing}"
        )
    return json.dumps(notice, sort_keys=True)


class Queue:
    """A durable, single-owner queue of signed envelopes for one agent.

    ``agent_id`` is the queue's owner, validated at open. Only envelopes
    addressed to that id are accepted; anything else is refused at
    :meth:`put`, never stored.
    """

    def __init__(
        self,
        path: str | Path,
        agent_id: str,
        context_ttl: timedelta = DEFAULT_CONTEXT_TTL,
        max_messages: int = MAX_QUEUE_MESSAGES,
        max_bytes: int = MAX_QUEUE_BYTES,
    ) -> None:
        validate_agent_id(agent_id)
        self.agent_id = agent_id
        self.path = Path(path)
        self.context_ttl = context_ttl
        # The local cap (issue #116): HUB.md's numbers, overridable per
        # deployment and per test. A message past either bound is refused by
        # ``put`` with :class:`QueueFullError`, never stored.
        self.max_messages = max_messages
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        self._closed = False
        # Notices served since the last message handed out. ``get`` interleaves
        # the two (issue #115): a notice backlog may delay a due message by at
        # most one notice, never starve it. In-memory only — a restart resets
        # the interleave, which only reorders, never loses, either side.
        self._notices_since_message = 0

        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Advisory lock first: one process owns the queue. Held for the
        # lifetime of this object; released by close().
        self._lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self._lock_file = open(self._lock_path, "w")  # noqa: SIM115
        try:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._lock_file.close()
            raise QueueLockedError(f"queue already open in another process: {self.path}")

        self._conn = sqlite3.connect(
            str(self.path), timeout=30.0, isolation_level=None, check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            # Additive migration: a queue file created before late arrivals were
            # delivered has no ``late`` column, and ``CREATE TABLE IF NOT EXISTS``
            # will not add one.
            columns = {
                row[1] for row in self._conn.execute("PRAGMA table_info(messages)")
            }
            if "late" not in columns:
                self._conn.execute(
                    "ALTER TABLE messages ADD COLUMN late INTEGER NOT NULL DEFAULT 0"
                )
            # Same additive migration for the notice dedupe key (issue #115).
            notice_columns = {
                row[1] for row in self._conn.execute("PRAGMA table_info(notices)")
            }
            if "dedupe_key" not in notice_columns:
                self._conn.execute(
                    "ALTER TABLE notices ADD COLUMN dedupe_key TEXT NOT NULL DEFAULT ''"
                )
            # Crash recovery: a message handed out but never acked is still
            # owed. It returns to the queue immediately — the crash is not a
            # failed delivery, so it does not consume backoff — but its
            # attempt count stands, so a poison message still dead-letters
            # after five handouts.
            self._conn.execute(
                "UPDATE messages SET state = 'queued', available_at = ?"
                " WHERE state = 'delivering'",
                (_ts(datetime.now(timezone.utc)),),
            )

    # -- lifecycle ------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._conn.close()
            finally:
                try:
                    fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
                finally:
                    self._lock_file.close()

    def __enter__(self) -> Queue:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- internal helpers ----------------------------------------------

    def _stream(self, context_id: str, sender: str, recipient: str) -> tuple[int, float | None]:
        row = self._conn.execute(
            "SELECT next_seq, gap_since FROM streams"
            " WHERE context_id = ? AND sender = ? AND recipient = ?",
            (context_id, sender, recipient),
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO streams (context_id, sender, recipient, next_seq, gap_since)"
                " VALUES (?, ?, ?, 0, NULL)",
                (context_id, sender, recipient),
            )
            return 0, None
        return row[0], row[1]

    def _refresh_gap(
        self, context_id: str, sender: str, recipient: str, moment: datetime
    ) -> None:
        """Keep ``gap_since`` true to whether a gap actually exists.

        A gap exists when a message is held past ``next_seq`` while nothing
        sits at ``next_seq``. The clock starts when the gap first opens and
        is not reset by later arrivals; it clears the moment the missing
        message arrives. Called after ``put`` and ``ack`` so the TTL in
        ``get`` can never fire on a gap that already closed — firing then
        would release held messages ahead of the message at ``next_seq``,
        i.e. out of order.
        """
        next_seq, gap_since = self._stream(context_id, sender, recipient)
        held_beyond = self._conn.execute(
            "SELECT 1 FROM messages WHERE context_id = ? AND sender = ?"
            " AND recipient = ? AND seq > ? LIMIT 1",
            (context_id, sender, recipient, next_seq),
        ).fetchone()
        at_next = self._conn.execute(
            "SELECT 1 FROM messages WHERE context_id = ? AND sender = ?"
            " AND recipient = ? AND seq = ? LIMIT 1",
            (context_id, sender, recipient, next_seq),
        ).fetchone()
        gap_exists = held_beyond is not None and at_next is None
        if gap_exists and gap_since is None:
            self._conn.execute(
                "UPDATE streams SET gap_since = ?"
                " WHERE context_id = ? AND sender = ? AND recipient = ?",
                (_ts(moment), context_id, sender, recipient),
            )
        elif not gap_exists and gap_since is not None:
            self._conn.execute(
                "UPDATE streams SET gap_since = NULL"
                " WHERE context_id = ? AND sender = ? AND recipient = ?",
                (context_id, sender, recipient),
            )

    def _sweep(self, now: datetime) -> None:
        """Return overdue deliveries to the queue; dead-letter the exhausted.

        A message handed out ``MAX_ATTEMPTS`` times without an ack is
        poison: after its last backoff elapses it moves to the dead-letter
        store instead of being handed out a sixth time.
        """
        moment = _ts(now)
        rows = self._conn.execute(
            "SELECT message_id, context_id, envelope_json, attempts FROM messages"
            " WHERE state = 'delivering' AND available_at <= ?",
            (moment,),
        ).fetchall()
        if not rows:
            return
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            for message_id, context_id, envelope_json, attempts in rows:
                if attempts >= MAX_ATTEMPTS:
                    self._conn.execute(
                        "INSERT INTO dead_letters"
                        " (message_id, context_id, envelope_json, attempts, dead_at, reason)"
                        " VALUES (?, ?, ?, ?, ?, ?)",
                        (message_id, context_id, envelope_json, attempts, moment,
                         f"undelivered after {attempts} attempts"),
                    )
                    self._queue_notice({
                        "kind": "dead",
                        "messageId": message_id,
                        "contextId": context_id,
                        "attempts": attempts,
                        "deadedAt": _iso(now),
                    }, now)
                    self._conn.execute(
                        "DELETE FROM messages WHERE message_id = ?", (message_id,)
                    )
                else:
                    self._conn.execute(
                        "UPDATE messages SET state = 'queued' WHERE message_id = ?",
                        (message_id,),
                    )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    # -- notices, late arrivals, retention -------------------------------

    def _queue_notice(self, notice: dict[str, Any], moment: datetime) -> None:
        """Record a transport frame the bridge must send. Caller holds the lock.

        One live notice per event (issue #115): a notice whose dedupe key
        matches a notice that is still pending or taken is not stored twice,
        so a sustained source of the same event cannot grow the backlog. A
        delivered notice does not block a later one for the same event.
        """
        dedupe_key = _notice_dedupe_key(notice)
        self._conn.execute(
            "INSERT INTO notices (kind, payload, created_at, state, available_at,"
            " dedupe_key) SELECT ?, ?, ?, 'pending', ?, ?"
            " WHERE NOT EXISTS (SELECT 1 FROM notices"
            " WHERE dedupe_key = ? AND state != 'delivered')",
            (notice["kind"], json.dumps(notice, sort_keys=True), _ts(moment),
             _ts(moment), dedupe_key, dedupe_key),
        )

    def _notice_due(self, moment: datetime) -> bool:
        """Whether a notice is due, without taking it. Caller holds the lock."""
        return self._conn.execute(
            "SELECT 1 FROM notices WHERE state != 'delivered'"
            " AND available_at <= ? LIMIT 1",
            (_ts(moment),),
        ).fetchone() is not None

    def _take_notice(self, moment: datetime) -> dict[str, Any] | None:
        """Hand out the oldest notice that is due, and mark it taken.

        Taken is not delivered. The bridge confirms with :meth:`confirm_notice`
        only once the frame is fsynced into its own log; until then the notice is
        re-offered after ``NOTICE_BACKOFF_SECONDS``. Marking it delivered here
        would lose it to any crash between the handout and the write — and the
        sender would never learn its message died, which is the point of the
        frame. Caller holds the lock.
        """
        row = self._conn.execute(
            "SELECT id, payload FROM notices WHERE state != 'delivered'"
            " AND available_at <= ? ORDER BY id LIMIT 1",
            (_ts(moment),),
        ).fetchone()
        if row is None:
            return None
        notice_id, payload = row
        self._conn.execute(
            "UPDATE notices SET state = 'taken', available_at = ? WHERE id = ?",
            (_ts(moment) + NOTICE_BACKOFF_SECONDS, notice_id),
        )
        notice = json.loads(payload)
        notice["_noticeId"] = notice_id
        return notice

    def confirm_notice(self, notice_id: int, now: datetime | None = None) -> bool:
        """Mark a taken notice delivered. Call after the frame is durable somewhere else."""
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE notices SET state = 'delivered'"
                " WHERE id = ? AND state != 'delivered'",
                (notice_id,),
            )
            return cursor.rowcount == 1

    def _was_skipped(self, context_id: str, sender: str, recipient: str, seq: int) -> bool:
        """Whether a gap release skipped this ``seq``, making an arrival late."""
        return self._conn.execute(
            "SELECT 1 FROM skipped WHERE context_id = ? AND sender = ?"
            " AND recipient = ? AND seq = ?",
            (context_id, sender, recipient, seq),
        ).fetchone() is not None

    def _prune_seen(self, moment: datetime) -> int:
        """Drop dedupe rows old enough that no duplicate can still be in flight.

        ``seen`` is the dedupe guarantee, so it must not be cleared wholesale.
        A message may set ``expiresAt`` up to 30 days out (SPEC §6), and a
        sender may retry until then, so the retention window is that bound —
        never shorter than the context TTL. Rows whose message is still live
        are kept regardless: deleting one would let the same id be stored
        twice, which the message table's primary key would reject with an
        ``IntegrityError`` instead of a clean ``duplicate``.
        """
        retention = max(SEEN_RETENTION, self.context_ttl)
        cutoff = _ts(moment - retention)
        cursor = self._conn.execute(
            "DELETE FROM seen WHERE first_seen < ? AND message_id NOT IN"
            " (SELECT message_id FROM messages)",
            (cutoff,),
        )
        self._conn.execute(
            "DELETE FROM notices WHERE state = 'delivered' AND created_at < ?", (cutoff,)
        )
        # ``skipped`` is the same growth class as ``seen``, one table over: a row is only
        # useful while a late arrival for that seq could still be accepted, which the same
        # retention window bounds.
        self._conn.execute(
            "DELETE FROM skipped WHERE released_at < ?", (cutoff,)
        )
        return cursor.rowcount

    # -- public API ------------------------------------------------------

    def seen(self, message_id: str) -> bool:
        """Whether this queue has already accepted ``message_id``.

        Durable and read-only, for the caller that must not do any work for a message it already
        holds (#69): a re-offered envelope after a lost ack is acknowledged and skipped before the
        gate is consulted, so it cannot move thread state a second time. Only meaningful **after**
        the envelope's signature and card were verified — a bare id must never be enough to
        suppress a message, or anyone who learned an id could bury the real one.
        """
        with self._lock:
            return self._conn.execute(
                "SELECT 1 FROM seen WHERE message_id = ?", (message_id,)
            ).fetchone() is not None

    def _usage_locked(self) -> tuple[int, int]:
        """Live messages held and the bytes they occupy. Caller holds the lock.

        Bytes are the stored envelope JSON as bytes — the same
        ``json.dumps(env, sort_keys=True)`` ``put`` stores, measured with
        ``LENGTH(CAST(... AS BLOB))`` so multibyte text counts as bytes,
        not characters.
        """
        row = self._conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(envelope_json AS BLOB))), 0)"
            " FROM messages"
        ).fetchone()
        return row[0], row[1]

    def put(
        self,
        env: dict[str, Any],
        now: datetime | None = None,
        transition: Any = None,
    ) -> str:
        """Store an envelope durably. Returns ``"accepted"``, ``"late"`` or ``"duplicate"``.

        Durable means: ``put`` returns only after the commit has been
        fsynced (``synchronous=FULL`` on a WAL database), so the message
        survives a kill before ack. A ``messageId`` already seen — live,
        acked, expired or dead — is accepted and dropped, never delivered
        twice. A ``seq`` below the last delivered for its stream is dropped
        the same way, and so is a second ``messageId`` reusing a ``seq``
        that is still held in the queue (issue #111). Raises ``ValueError`` on a malformed or already
        expired envelope, on a sealed (form 2) envelope, whose ``contextId``
        is inside ``sealed`` so the stream key cannot be computed before
        decryption, on an envelope not addressed to this queue's owner, and
        on a multi-recipient envelope — the hub does fan-out, this queue
        does not.

        ``transition`` is applied on this queue's own connection inside the
        insert's transaction (#69): the gate's answer is only half the fact,
        and the thread state it implies must not outlive a message that was
        never stored. A duplicate returns before the transaction opens and
        therefore applies nothing — the first accepted copy already did.
        The object only has to offer ``apply(conn, now)`` and must write in
        the same database this queue owns (the bridge opens ``Threads`` on
        ``queue.db`` for exactly that reason); a table in another file would
        make the word "together" a lie.

        Raises :class:`QueueFullError` when the local queue is at its cap
        (issue #116): the message is refused, nothing is stored, and no
        thread state is applied — the caller leaves it at the hub to be
        re-offered. Duplicates are still answered ``"duplicate"`` at cap,
        so a re-offered id is acked away rather than refused forever.
        """
        moment = now or datetime.now(timezone.utc)
        if not isinstance(env, dict) or "message" not in env:
            raise ValueError(
                "queue accepts form 1 envelopes only: a sealed (form 2) envelope"
                " carries its contextId inside sealed, so it cannot be ordered"
                " before decryption"
            )
        reason = _envelope.validate(env, moment)
        if reason:
            raise ValueError(f"invalid envelope: {reason}")
        message = env["message"]
        message_id = message["messageId"]
        context_id = message["contextId"]
        sender = env["from"]
        recipients = env["to"]
        if len(recipients) > 1:
            raise ValueError(
                "hub fan-out is not implemented: one queue serves one agent"
            )
        if recipients[0] != self.agent_id:
            raise ValueError(f"envelope is not addressed to {self.agent_id}")
        recipient = recipients[0]
        seq = env["seq"]
        with self._lock:
            if self._conn.execute(
                "SELECT 1 FROM seen WHERE message_id = ?", (message_id,)
            ).fetchone():
                return "duplicate"
            next_seq, _gap_since = self._stream(context_id, sender, recipient)
            # A ``seq`` below the last delivered is one of two things, and the
            # difference decides whether a live message is destroyed:
            #   * it was already delivered (or superseded) — a duplicate;
            #   * a gap release skipped it, so it is a late arrival — the spec
            #     forbids dropping it silently; it is delivered out of order
            #     with a ``late`` notice (issue #19).
            # ``skipped`` records exactly the second case, so the two never
            # have to be guessed apart.
            late = seq < next_seq and self._was_skipped(
                context_id, sender, recipient, seq
            )
            if seq < next_seq and not late:
                # A seq below the stream's next is spent. If this envelope says it retries a
                # message we have already seen, it is a retry and silence is correct — the
                # original was delivered. Anything else is a *different* message arriving at a
                # seq another message already used, which is the sender breaking the ordering
                # contract. Answering "duplicate" there is how a follow-up question vanished
                # while every log said delivered (#142): the bridge acked it and the hub told
                # the sender a bridge had taken it. It is refused by name instead.
                if _retries_a_seen_message(message, self._conn):
                    self._conn.execute(
                        "INSERT INTO seen (message_id, context_id, first_seen)"
                        " VALUES (?, ?, ?)",
                        (message_id, context_id, _ts(moment)),
                    )
                    return "duplicate"
                return "conflict"
            if self._conn.execute(
                "SELECT 1 FROM messages WHERE context_id = ? AND sender = ?"
                " AND recipient = ? AND seq = ?",
                (context_id, sender, recipient, seq),
            ).fetchone():
                # A second id competing for a seq that is still held — at
                # ``next_seq`` or held behind a gap — is a duplicate, not a
                # second row (issue #111). Accepting it would strand it: once
                # the first is acked ``next_seq`` advances past the seq, and
                # ``get`` only selects ``seq = next_seq`` or a late arrival,
                # so the second row could never be delivered. The ``seen``
                # insert is what makes a re-offer of the refused id a
                # duplicate too, rather than a resurrection.
                if _retries_a_seen_message(message, self._conn):
                    self._conn.execute(
                        "INSERT INTO seen (message_id, context_id, first_seen)"
                        " VALUES (?, ?, ?)",
                        (message_id, context_id, _ts(moment)),
                    )
                    return "duplicate"
                return "conflict"
            # The local cap (issue #116), checked after the duplicate answers
            # so a re-offer at cap is still a duplicate: the hub cap alone
            # does not bound this queue, because the hub copy is deleted on
            # ack and an undrained local queue would otherwise grow without
            # limit. Under the lock, with a single owner, the check and the
            # insert below cannot interleave.
            count, stored_bytes = self._usage_locked()
            new_bytes = len(json.dumps(env, sort_keys=True).encode("utf-8"))
            if count >= self.max_messages or stored_bytes + new_bytes > self.max_bytes:
                raise QueueFullError(
                    f"local queue at cap: {count} messages, {stored_bytes} bytes"
                    f" stored (cap {self.max_messages} messages or"
                    f" {self.max_bytes} bytes)"
                )
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "INSERT INTO seen (message_id, context_id, first_seen)"
                    " VALUES (?, ?, ?)",
                    (message_id, context_id, _ts(moment)),
                )
                self._conn.execute(
                    "INSERT INTO messages (message_id, context_id, sender, recipient,"
                    " seq, envelope_json, expires_at, state, attempts, available_at,"
                    " inserted_at, late) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?)",
                    (message_id, context_id, sender, recipient, seq,
                     json.dumps(env, sort_keys=True),
                     _ts(_parse_iso(env["expiresAt"])), _ts(moment), _ts(moment),
                     1 if late else 0),
                )
                if late:
                    self._conn.execute(
                        "DELETE FROM skipped WHERE context_id = ? AND sender = ?"
                        " AND recipient = ? AND seq = ?",
                        (context_id, sender, recipient, seq),
                    )
                    self._queue_notice({
                        "kind": "late",
                        "messageId": message_id,
                        "contextId": context_id,
                        "seq": seq,
                        "from": sender,
                        "to": recipient,
                        "detectedAt": _iso(moment),
                    }, moment)
                if transition is not None:
                    # Same transaction as the insert: a failure above rolls the thread state back
                    # with the message, and a success commits both (#69).
                    transition.apply(self._conn, moment)
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._refresh_gap(context_id, sender, recipient, moment)
            return "late" if late else "accepted"

    def get(self, now: datetime | None = None) -> dict[str, Any] | None:
        """Return the next envelope due for delivery, or ``None``.

        Hands out the oldest due message whose ``seq`` is the next expected
        for its stream — never out of order, never before its backoff
        elapses. Each handout is one delivery attempt: the message is
        marked ``delivering`` with its next availability set by the
        backoff, so an unacked message is re-offered only after the wait,
        and a fifth unacked handout dead-letters it instead of a sixth.

        May also return a gap notice — ``{"kind": "gap", ...}``, a
        transport frame, not a Message — when a stream's gap has outlived
        the context TTL: the held messages are then released in order on
        subsequent calls. Notices and messages interleave: the oldest due
        notice still goes first, but a due message is delayed by at most one
        notice (issue #115). Returns ``None`` when nothing is due.
        """
        moment = now or datetime.now(timezone.utc)
        with self._lock:
            self._sweep(moment)
            # Releasing an expired gap queues its notice rather than returning it, so a crash
            # after the release cannot lose the only signal that messages were skipped.
            self._release_expired_gap(moment)
            row = self._conn.execute(
                "SELECT m.message_id, m.envelope_json FROM messages m"
                " JOIN streams s ON s.context_id = m.context_id"
                "   AND s.sender = m.sender AND s.recipient = m.recipient"
                " WHERE m.state = 'queued' AND m.available_at <= ?"
                # In-order mail first; a late arrival is deliverable even though
                # its seq is behind the stream (issue #19).
                "   AND (m.seq = s.next_seq OR m.late = 1)"
                " ORDER BY CASE WHEN m.seq = s.next_seq THEN 0 ELSE 1 END,"
                "   m.inserted_at, m.message_id LIMIT 1",
                (_ts(moment),),
            ).fetchone()
            # A pending notice goes out before more mail: the receiver must be told a gap was
            # released, or that a message it will never see died, before the messages after it.
            # But strict priority lets a notice backlog starve mail, so the two interleave
            # (issue #115): a due message is delayed by at most one notice, and a backlog
            # still drains freely when no message is due.
            if self._notice_due(moment) and (
                row is None or self._notices_since_message == 0
            ):
                pending = self._take_notice(moment)
                if pending is not None:
                    self._notices_since_message += 1
                    return pending
            if row is None:
                return None
            message_id, envelope_json = row
            attempts = self._conn.execute(
                "SELECT attempts FROM messages WHERE message_id = ?", (message_id,)
            ).fetchone()[0] + 1
            backoff = BACKOFF_SECONDS[min(attempts - 1, MAX_ATTEMPTS - 1)]
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "UPDATE messages SET state = 'delivering', attempts = ?,"
                    " available_at = ? WHERE message_id = ?",
                    (attempts, _ts(moment) + backoff, message_id),
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._notices_since_message = 0
            return json.loads(envelope_json)

    def _release_expired_gap(self, moment: datetime) -> bool:
        """Release one stream whose gap outlived the context TTL, in order.

        Returns whether anything was released. The stream's ``next_seq`` jumps
        to the first held message, so the held messages become deliverable in
        order on subsequent ``get`` calls. The skipped seqs are recorded in
        ``skipped``, so a message bearing one that arrives later is delivered as
        a *late* arrival with its own notice rather than dropped as a duplicate
        (issue #19). The gap notice is queued, not returned: it must survive a
        crash between the release and the bridge writing it out.
        """
        deadline = _ts(moment) - self.context_ttl.total_seconds()
        row = self._conn.execute(
            "SELECT s.context_id, s.sender, s.recipient, s.next_seq,"
            " MIN(m.seq) FROM streams s"
            " JOIN messages m ON m.context_id = s.context_id"
            "   AND m.sender = s.sender AND m.recipient = s.recipient"
            " WHERE s.gap_since IS NOT NULL AND s.gap_since <= ?"
            "   AND m.seq > s.next_seq AND m.state = 'queued'"
            "   AND NOT EXISTS (SELECT 1 FROM messages m2 WHERE m2.context_id = s.context_id"
            "     AND m2.sender = s.sender AND m2.recipient = s.recipient"
            "     AND m2.seq = s.next_seq)"
            " GROUP BY s.context_id, s.sender, s.recipient, s.next_seq"
            " ORDER BY s.gap_since LIMIT 1",
            (deadline,),
        ).fetchone()
        if row is None:
            return False
        context_id, sender, recipient, next_seq, first_held = row
        missing = [
            seq for seq in range(next_seq, first_held)
            if not self._conn.execute(
                "SELECT 1 FROM messages WHERE context_id = ? AND sender = ?"
                " AND recipient = ? AND seq = ?",
                (context_id, sender, recipient, seq),
            ).fetchone()
        ]
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "UPDATE streams SET next_seq = ?, gap_since = NULL"
                " WHERE context_id = ? AND sender = ? AND recipient = ?",
                (first_held, context_id, sender, recipient),
            )
            # These seqs are now dead as far as ordering is concerned, but a
            # message bearing one may still arrive. Recording them is what lets
            # ``put`` tell a late arrival (deliver it, say so) from a duplicate
            # (drop it, silently) — the two are identical on ``seq`` alone.
            for seq in missing:
                self._conn.execute(
                    "INSERT OR IGNORE INTO skipped"
                    " (context_id, sender, recipient, seq, released_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (context_id, sender, recipient, seq, _ts(moment)),
                )
            # The notice belongs inside this transaction, not after it: a crash between the
            # release and a separate insert would leave the streams advanced and ``skipped``
            # populated with nothing to tell the receiver that seqs were passed over.
            self._queue_notice({
                "kind": "gap",
                "contextId": context_id,
                "from": sender,
                "to": recipient,
                "missing": missing,
                "releasedAt": _iso(moment),
            }, moment)
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return True

    def ack(self, message_id: str, now: datetime | None = None) -> bool:
        """Mark a message delivered. Returns ``False`` when unknown.

        The ack is the sender's licence to drop its copy, so it only lands
        on a message this queue actually handed out or holds. Acking
        advances the stream past the acked ``seq`` and closes the gap if
        the missing message was the one acked.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT context_id, sender, recipient, seq FROM messages"
                " WHERE message_id = ?",
                (message_id,),
            ).fetchone()
            if row is None:
                return False
            context_id, sender, recipient, seq = row
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "DELETE FROM messages WHERE message_id = ?", (message_id,)
                )
                stream = self._conn.execute(
                    "SELECT next_seq FROM streams"
                    " WHERE context_id = ? AND sender = ? AND recipient = ?",
                    (context_id, sender, recipient),
                ).fetchone()
                if stream and seq == stream[0]:
                    # The next message to deliver is now seq + 1. Messages
                    # already queued at that seq are undelivered by
                    # definition (delivered rows are deleted), so nothing
                    # is skipped: get() hands them out when their turn comes.
                    self._conn.execute(
                        "UPDATE streams SET next_seq = ?"
                        " WHERE context_id = ? AND sender = ? AND recipient = ?",
                        (seq + 1, context_id, sender, recipient),
                    )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._refresh_gap(context_id, sender, recipient,
                              now or datetime.now(timezone.utc))
            return True

    def resend(
        self,
        context_id: str,
        seq: int,
        sender: str | None = None,
        recipient: str | None = None,
    ) -> dict[str, Any]:
        """Report what is missing for ``context_id`` at ``seq`` (§6 RESEND).

        ``missing`` lists every ``seq`` below the highest held message
        that is neither delivered nor held, per stream; without
        ``sender``/``recipient`` it aggregates across the pairs sharing
        the context. ``available`` says whether the requested ``seq`` is
        held here (so the requester need not ask the sender for it).
        """
        with self._lock:
            conditions = ["context_id = ?"]
            params: list[Any] = [context_id]
            if sender is not None:
                conditions.append("sender = ?")
                params.append(sender)
            if recipient is not None:
                conditions.append("recipient = ?")
                params.append(recipient)
            where = " AND ".join(conditions)
            streams = self._conn.execute(
                f"SELECT sender, recipient, next_seq FROM streams WHERE {where}",
                params,
            ).fetchall()
            missing: set[int] = set()
            next_expected: int | None = None
            for stream_sender, stream_recipient, next_seq in streams:
                held = [
                    r[0] for r in self._conn.execute(
                        "SELECT seq FROM messages WHERE context_id = ?"
                        " AND sender = ? AND recipient = ? AND state = 'queued'",
                        (context_id, stream_sender, stream_recipient),
                    ).fetchall()
                ]
                if not held:
                    continue
                top = max(held)
                present = set(held)
                missing.update(s for s in range(next_seq, top) if s not in present)
                next_expected = next_seq if next_expected is None else min(next_expected, next_seq)
            available = self._conn.execute(
                f"SELECT 1 FROM messages WHERE {where} AND seq = ?",
                [*params, seq],
            ).fetchone() is not None
            return {
                "contextId": context_id,
                "requestedSeq": seq,
                "missing": sorted(missing),
                "nextExpected": next_expected,
                "available": available,
            }

    def expire(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """Drop messages past ``expiresAt``; return one frame per message.

        Each frame is the §6 unsigned transport frame — ``{"kind":
        "expired", "messageId", "contextId", "expiredAt"}`` — not a
        ``Message`` and not signed as the recipient, who never saw the
        message. Dropped ids stay in ``seen``, so a re-put is still a
        duplicate rather than a resurrection.
        """
        moment = now or datetime.now(timezone.utc)
        frames: list[dict[str, Any]] = []
        with self._lock:
            self._sweep(moment)
            rows = self._conn.execute(
                "SELECT message_id, context_id, sender, recipient FROM messages"
                " WHERE expires_at <= ?",
                (_ts(moment),),
            ).fetchall()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for message_id, context_id, sender, recipient in rows:
                    self._conn.execute(
                        "DELETE FROM messages WHERE message_id = ?", (message_id,)
                    )
                    frames.append({
                        "kind": "expired",
                        "messageId": message_id,
                        "contextId": context_id,
                        "expiredAt": _iso(moment),
                    })
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            for _mid, context_id, sender, recipient in rows:
                self._refresh_gap(context_id, sender, recipient, moment)
            self._prune_seen(moment)
            return frames

    def depth(self) -> int:
        """Number of live messages held (queued or delivering). Read-only; used by the
        transport's health endpoint (§10 queue depth per recipient)."""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM messages").fetchone()
            return row[0]

    def usage(self) -> dict[str, int]:
        """Live messages held and the bytes they occupy. Read-only; the cap's
        meter — see :meth:`put` and issue #116."""
        with self._lock:
            count, stored_bytes = self._usage_locked()
            return {"messages": count, "bytes": stored_bytes}

    def dead_letter(self) -> list[dict[str, Any]]:
        """List dead-lettered messages, oldest first, for the owner."""
        with self._lock:
            self._sweep(datetime.now(timezone.utc))
            rows = self._conn.execute(
                "SELECT message_id, context_id, envelope_json, attempts, dead_at, reason"
                " FROM dead_letters ORDER BY dead_at, message_id"
            ).fetchall()
            return [
                {
                    "messageId": message_id,
                    "contextId": context_id,
                    "envelope": json.loads(envelope_json),
                    "attempts": attempts,
                    "deadAt": _iso(datetime.fromtimestamp(dead_at, timezone.utc)),
                    "reason": reason,
                }
                for message_id, context_id, envelope_json, attempts, dead_at, reason in rows
            ]
