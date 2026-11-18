"""The hub: a post office for agents (``docs/HUB.md`` v0.2, Phase 2).

The hub stores signed envelopes for an agent that is not currently connected,
hands them over when it is, and deletes them when the recipient says they are
handled. It is not a participant: it never decides whether a sender is welcome
(that is ``knok.gate`` on the recipient), never orders per-context traffic, and
never reads a ``Message`` body — routing, dedupe and expiry are header work.

Trust and keys — read this before touching this module:

* The hub has **its own identity** (an Ed25519 keypair and a card in the same
  registry as the agents) because it emits transport frames (``expired``) that
  a bridge must be able to distinguish from a forged envelope dropped into its
  mailbox by any other agent. It signs those frames with its own key.
* The hub **never opens an agent's key file.** It receives the hub's own
  ``Identity`` — already loaded by the operator process that starts it — and
  the agents' *signed cards*, which carry public keys only. There is no key
  path, no PEM read and no ``Identity.load()`` anywhere in this module. If a
  future change seems to need one, that change is wrong: keys live in the
  agent's own volume, ``0600``, and a hub bug must not be able to reach them.

Authentication (HUB.md §Authentication): no bearer token, no shared secret.

* Deposit (``POST /v1/mail``): the body *is* the signed envelope; the hub
  verifies it against the sender's registered card and requires
  ``envelope["from"] == card.agent_id``.
* Fetch, ack, presence, health: the bridge signs a request document
  ``{"agent", "nonce", "at", "method", "target", "bodySha256"}`` over its JCS
  bytes, sent as ``X-Knok-*`` headers. The signed ``target`` is the exact
  request-target, query string included; the hub verifies against the target
  exactly as received, so a middlebox that reorders or rewrites the query
  breaks verification — that is the point. ``at`` must be within 5 minutes of
  the hub's clock; nonces are stored durably, accepted once per agent within
  10 minutes, and survive restart.

Refusals (HUB.md §Refusals): every authentication or identity failure, and
every permanent deposit refusal, returns the one shared 403 body from
``knok.transport`` — no reason is ever leaked, and no handler path ever lets
an exception escape (a 500 or a dropped connection would be distinguishable
from every other refusal, §9). The one exception, on a private hub only, is
over-capacity: 429 with a retry hint, because retryable and permanent are
honestly different and a sender that cannot tell them apart either retries a
bad signature forever or gives up on a full box.

Storage: one SQLite file, WAL + ``synchronous=FULL``, one connection guarded
by one lock, single-owner via an advisory ``flock`` — the same durability
shape as ``knok.queue``. A deposit is durable when ``POST /v1/mail`` returns
202: the commit is fsynced before the answer. Nonces, ``last_seen`` and
dropped-frame counts live in the same store, so a restart preserves mail and
nonces alike.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import http.server
import json
import logging
import sqlite3
import threading
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .agentcard import verify_card
from .canonical import CanonicalisationError, canonical_bytes
from .envelope import verify_envelope
from .identity import (
    Identity,
    b64url,
    b64url_decode,
    public_key_from_b64,
    verify_signature,
)
from .transport import MAX_ENVELOPE_BYTES, REFUSAL_BODY, REFUSAL_STATUS

__all__ = [
    "Hub",
    "HubLockedError",
    "MAX_MAILBOX_BYTES",
    "MAX_MAILBOX_MESSAGES",
    "sign_expired_frame",
    "verify_frame",
]

log = logging.getLogger(__name__)

#: Mailbox cap (HUB.md): 10,000 envelopes or 256 MiB per agent, first hit wins.
MAX_MAILBOX_MESSAGES = 10_000
MAX_MAILBOX_BYTES = 256 * 1024 * 1024
#: Skew bound on the signed ``at`` field: 5 minutes either way.
SKEW_SECONDS = 300
#: Nonces are accepted once per agent within 10 minutes — twice the skew
#: window, so a request cannot be replayed after skew stops rejecting it.
NONCE_WINDOW_SECONDS = 600
#: The expiry sweep runs at least every 60 seconds (HUB.md).
SWEEP_INTERVAL_SECONDS = 60
#: Presence answers ``online`` when ``last_seen`` is younger than 90 seconds.
PRESENCE_ONLINE_SECONDS = 90
#: A hub-signed frame lives in the sender's mailbox under the same TTL as mail.
FRAME_TTL = timedelta(hours=72)
#: Fetch paging: default 50, hard ceiling 100 (HUB.md names no bound).
FETCH_DEFAULT_LIMIT = 50
FETCH_MAX_LIMIT = 100
#: Over-capacity retry hint (HUB.md names no number; 60 s is the sweep tick).
RETRY_AFTER_SECONDS = 60

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mail (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient    TEXT NOT NULL,
    sender       TEXT NOT NULL,
    message_id   TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('envelope', 'frame')),
    payload_json TEXT NOT NULL,
    size         INTEGER NOT NULL,
    expires_at   REAL NOT NULL,
    inserted_at  REAL NOT NULL,
    UNIQUE (recipient, sender, message_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_mail_recipient ON mail (recipient, id);
CREATE INDEX IF NOT EXISTS idx_mail_lookup ON mail (recipient, message_id);
CREATE TABLE IF NOT EXISTS nonces (
    agent    TEXT NOT NULL,
    nonce    TEXT NOT NULL,
    seen_at  REAL NOT NULL,
    PRIMARY KEY (agent, nonce)
);
CREATE TABLE IF NOT EXISTS presence (
    agent     TEXT PRIMARY KEY,
    last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS dropped_frames (
    owner   TEXT PRIMARY KEY,
    count   INTEGER NOT NULL DEFAULT 0,
    last_at REAL
);
"""


class HubLockedError(RuntimeError):
    """A second process tried to open a hub store that is already owned."""


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


def _ts(moment: datetime) -> float:
    return moment.timestamp()


def _encode_cursor(row_id: int) -> str:
    return b64url(str(row_id).encode("ascii"))


def _decode_cursor(cursor: str) -> int:
    try:
        return int(b64url_decode(cursor).decode("ascii"))
    except Exception as exc:
        raise ValueError(f"bad cursor: {cursor!r}") from exc


def sign_expired_frame(
    identity: Identity,
    *,
    message_id: str,
    context_id: str,
    recipient_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Sign the HUB.md ``expired`` transport frame with the hub's own key.

    The frame is not a ``Message`` and never enters a thread. ``from`` is the
    hub, ``to`` is the sender of the envelope that expired.
    """
    moment = now or datetime.now(timezone.utc)
    frame = {
        "kind": "expired",
        "messageId": message_id,
        "contextId": context_id,
        "expiredAt": _iso(moment),
        "from": identity.agent_id,
        "to": [recipient_id],
    }
    signed = dict(frame)
    signed["signature"] = identity.sign(canonical_bytes(frame))
    return signed


def verify_frame(frame: Any, public_key) -> bool:
    """Verify a hub-signed transport frame. Never raises.

    Only ``expired`` frames exist in v1: HUB.md names ``dead`` frames too but
    defines no hub event that produces one, so this slice emits none and a
    ``dead`` frame does not verify here.
    """
    if not isinstance(frame, dict) or frame.get("kind") != "expired":
        return False
    for field in ("messageId", "contextId", "expiredAt", "from", "to"):
        if not frame.get(field):
            return False
    if not isinstance(frame.get("to"), list) or len(frame["to"]) != 1:
        return False
    if _parse_iso(frame.get("expiredAt")) is None:
        return False
    signature = frame.get("signature")
    if not isinstance(signature, str):
        return False
    body = {key: value for key, value in frame.items() if key != "signature"}
    try:
        payload = canonical_bytes(body)
    except (CanonicalisationError, Exception):
        return False
    return verify_signature(public_key, payload, signature)


class _Refused(Exception):
    """An outcome that is the shared 403. Raised internally, never across the wire."""


class _OverCapacity(Exception):
    """The recipient's mailbox is at cap: the one 429 in the contract."""


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # one request per connection; no keep-alive state
    server_version = "KnokHub/0.1"

    def log_message(self, *args: object) -> None:  # keep demo/test output clean
        pass

    # -- helpers ---------------------------------------------------------

    def _refuse(self) -> None:
        self._send(REFUSAL_STATUS, REFUSAL_BODY)

    def _over_capacity(self) -> None:
        body = json.dumps(
            {"error": "over-capacity", "retryAfterSeconds": RETRY_AFTER_SECONDS},
            sort_keys=True,
        ).encode("ascii")
        self.send_response(429)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Retry-After", str(RETRY_AFTER_SECONDS))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes | None:
        """Read exactly Content-Length bytes, capped at 64 KiB. None refuses."""
        length = self.headers.get("Content-Length")
        try:
            size = int(length) if length is not None else -1
        except ValueError:
            return None
        if size < 0 or size > MAX_ENVELOPE_BYTES:
            if size > MAX_ENVELOPE_BYTES:
                self.rfile.read(MAX_ENVELOPE_BYTES + 1)
            return None
        raw = self.rfile.read(size)
        return raw if len(raw) == size else None

    def _json_body(self) -> Any | None:
        raw = self._read_body()
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return None

    # -- routes ----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - http.server names the method
        # Every handler path ends in the shared 403: an exception escaping
        # here would be a distinguishable refusal (§9, slice 4 lesson).
        try:
            self._dispatch_get()
        except Exception:
            self._refuse()

    def _dispatch_get(self) -> None:
        hub: Hub = self.server.hub  # type: ignore[attr-defined]
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/v1/mail":
            self._fetch(hub)
        elif path == "/v1/health":
            self._health(hub)
        elif path.startswith("/v1/presence/"):
            target = urllib.parse.unquote(path[len("/v1/presence/"):])
            self._presence(hub, target)
        else:
            self._refuse()

    def do_POST(self) -> None:  # noqa: N802 - http.server names the method
        try:
            self._dispatch_post()
        except Exception:
            self._refuse()

    def _dispatch_post(self) -> None:
        hub: Hub = self.server.hub  # type: ignore[attr-defined]
        path = urllib.parse.urlparse(self.path).path
        if path == "/v1/mail":
            self._deposit(hub)
        elif path == "/v1/mail/ack":
            self._ack(hub)
        else:
            self._refuse()

    # -- endpoints --------------------------------------------------------

    def _deposit(self, hub: "Hub") -> None:
        # Over-cap bodies are refused without being read to the end.
        raw = self._read_body()
        if raw is None:
            self._refuse()
            return
        try:
            envelope = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self._refuse()
            return
        try:
            outcome, message_id = hub.deposit(envelope, len(raw))
        except _OverCapacity:
            self._over_capacity()
            return
        except _Refused:
            self._refuse()
            return
        # 202 either way: a duplicate deposit is accepted, stores nothing.
        self._send(202, json.dumps(
            {"accepted": True, "messageId": message_id}, sort_keys=True,
        ).encode("ascii"))

    def _fetch(self, hub: "Hub") -> None:
        agent = hub.authenticate(
            method="GET", target=self.path, headers=self.headers, body=b""
        )
        if agent is None:
            self._refuse()
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            limit = self._limit(query)
            after = self._cursor(query)
            messages, next_cursor = hub.fetch(agent, after=after, limit=limit)
        except _Refused:
            self._refuse()
            return
        self._send(200, json.dumps(
            {"messages": messages, "next": next_cursor}, sort_keys=True,
        ).encode("ascii"))

    @staticmethod
    def _limit(query: dict[str, list[str]]) -> int:
        values = query.get("limit", [])
        if len(values) > 1:
            raise _Refused("repeated limit")
        if not values:
            return FETCH_DEFAULT_LIMIT
        try:
            limit = int(values[0])
        except ValueError as exc:
            raise _Refused("limit is not an integer") from exc
        if limit < 1:
            raise _Refused("limit must be positive")
        return min(limit, FETCH_MAX_LIMIT)

    @staticmethod
    def _cursor(query: dict[str, list[str]]) -> int:
        values = query.get("cursor", [])
        if len(values) > 1:
            raise _Refused("repeated cursor")
        if not values or not values[0]:
            return 0
        try:
            return _decode_cursor(values[0])
        except ValueError as exc:
            raise _Refused("bad cursor") from exc

    def _ack(self, hub: "Hub") -> None:
        raw = self._read_body()
        if raw is None:
            self._refuse()
            return
        agent = hub.authenticate(
            method="POST", target=self.path, headers=self.headers, body=raw
        )
        if agent is None:
            self._refuse()
            return
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self._refuse()
            return
        if not isinstance(body, dict) or not isinstance(body.get("messageIds"), list) \
                or not all(isinstance(item, str) for item in body["messageIds"]):
            self._refuse()
            return
        acked = hub.ack(agent, body["messageIds"])
        self._send(200, json.dumps({"acked": acked}, sort_keys=True).encode("ascii"))

    def _presence(self, hub: "Hub", target: str) -> None:
        agent = hub.authenticate(
            method="GET", target=self.path, headers=self.headers, body=b""
        )
        if agent is None:
            self._refuse()
            return
        online, last_seen = hub.presence(target)
        self._send(200, json.dumps(
            {"online": online, "lastSeen": last_seen}, sort_keys=True,
        ).encode("ascii"))

    def _health(self, hub: "Hub") -> None:
        agent = hub.authenticate(
            method="GET", target=self.path, headers=self.headers, body=b""
        )
        if agent is None:
            self._refuse()
            return
        queued, dropped = hub.health(agent)
        # Caller's own mailbox only: no agent id, no global depth (§10/#25).
        self._send(200, json.dumps(
            {"status": "ok", "queued": queued, "droppedFrames": dropped},
            sort_keys=True,
        ).encode("ascii"))


class Hub:
    """One hub: its store, its keys, one loopback port.

    ``identity`` is the hub's own identity, loaded by the operator process —
    never an agent's key, and never loaded from a path here (see the module
    docstring). ``cards`` maps every agent id to that agent's signed Agent
    Card JWS; ``registry`` maps fingerprint -> public key (b64) and is the
    only trust root for those cards (§4: no trust-on-first-use).
    """

    def __init__(
        self,
        *,
        path: str | Path,
        identity: Identity,
        cards: dict[str, dict[str, Any]],
        registry: dict[str, str],
        host: str = "127.0.0.1",
        port: int = 0,
        max_messages: int = MAX_MAILBOX_MESSAGES,
        max_bytes: int = MAX_MAILBOX_BYTES,
        sweep_interval: float = SWEEP_INTERVAL_SECONDS,
    ):
        # The hub's id is operator-chosen, not an agent id: validate_agent_id
        # would reject the reserved name "hub", which is exactly the point —
        # no *agent* may be called hub, so the hub's own id can never collide
        # with one. Only the shape is checked here.
        if identity.agent_id.count("@") != 1 or not all(
            identity.agent_id.split("@")
        ):
            raise ValueError(f"invalid hub id {identity.agent_id!r}: expected name@domain")
        self.identity = identity
        self.agent_id = identity.agent_id
        self.cards = dict(cards)
        self.registry = dict(registry)
        self.host = host
        self.port = port
        self.max_messages = max_messages
        self.max_bytes = max_bytes
        self.sweep_interval = sweep_interval
        self.path = Path(path)
        self._lock = threading.RLock()
        self._closed = False
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._sweeper: threading.Thread | None = None

        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Advisory lock first: one process owns the hub store, as with Queue.
        self._lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self._lock_file = open(self._lock_path, "w")  # noqa: SIM115
        try:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._lock_file.close()
            raise HubLockedError(f"hub store already open in another process: {self.path}")

        self._conn = sqlite3.connect(
            str(self.path), timeout=30.0, isolation_level=None, check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(_SCHEMA)

    # -- lifecycle ------------------------------------------------------

    @property
    def url(self) -> str:
        port = self._server.server_address[1] if self._server else self.port
        return f"http://{self.host}:{port}"

    def start(self) -> "Hub":
        server = http.server.ThreadingHTTPServer((self.host, self.port), _Handler)
        server.daemon_threads = True
        server.hub = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name=f"knok-hub-{self.agent_id}", daemon=True
        )
        self._thread.start()
        self._stop_event.clear()
        self._sweeper = threading.Thread(
            target=self._sweep_loop, name=f"knok-hub-sweep-{self.agent_id}", daemon=True
        )
        self._sweeper.start()
        return self

    def stop(self) -> None:
        self._stop_event.set()
        if self._sweeper is not None:
            self._sweeper.join(timeout=5)
            self._sweeper = None
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        with self._lock:
            if not self._closed:
                self._closed = True
                try:
                    self._conn.close()
                finally:
                    try:
                        fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
                    finally:
                        self._lock_file.close()

    def __enter__(self) -> "Hub":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _sweep_loop(self) -> None:
        while not self._stop_event.wait(self.sweep_interval):
            try:
                self.sweep()
            except Exception:
                # The sweeper must never take the hub down, and must never
                # surface a distinguishable failure to a request handler.
                log.exception("hub sweep failed; retrying next interval")

    # -- cards ----------------------------------------------------------

    def _card_public_key(self, agent_id: str):
        """The registered public key for ``agent_id``, or None. Never raises."""
        card = self.cards.get(agent_id)
        if card is None:
            return None
        ok, _reason = verify_card(card, self.registry, expected_agent_id=agent_id)
        if not ok:
            return None
        try:
            card_body = json.loads(b64url_decode(card["payload"]))
            return public_key_from_b64(card_body["bridge"]["publicKey"])
        except Exception:
            return None

    # -- authentication ---------------------------------------------------

    def authenticate(
        self,
        *,
        method: str,
        target: str,
        headers,
        body: bytes,
        now: datetime | None = None,
    ) -> str | None:
        """Verify a signed request document. Returns the agent id, or None to refuse.

        Never raises: any failure is the same refusal. The document is rebuilt
        from the request actually received — method, exact request-target, body
        hash — so the signature covers what the hub is about to act on.
        """
        moment = now or datetime.now(timezone.utc)
        agent = headers.get("X-Knok-Agent")
        nonce = headers.get("X-Knok-Nonce")
        at = headers.get("X-Knok-At")
        signature = headers.get("X-Knok-Signature")
        if not all(isinstance(v, str) and v for v in (agent, nonce, at, signature)):
            return None
        public_key = self._card_public_key(agent)
        if public_key is None:
            return None  # unknown agent, or a card the registry never published
        at_dt = _parse_iso(at)
        if at_dt is None:
            return None
        if abs((moment - at_dt).total_seconds()) > SKEW_SECONDS:
            return None  # bad skew, signed or not
        # ``X-Knok-Agent`` must equal the ``agent`` inside the signed
        # document. The document is rebuilt from this header, so a signed
        # document naming a different agent fails verification here — the
        # check is the signature, not a string comparison after it.
        document = {
            "agent": agent,
            "nonce": nonce,
            "at": at,
            "method": method,
            "target": target,
            "bodySha256": hashlib.sha256(body).hexdigest(),
        }
        try:
            payload = canonical_bytes(document)
        except (CanonicalisationError, Exception):
            return None
        if not verify_signature(public_key, payload, signature):
            return None
        if not self._claim_nonce(agent, nonce, moment):
            return None  # replay: this (agent, nonce) was already used
        self._note_seen(agent, moment)
        return agent

    def _claim_nonce(self, agent: str, nonce: str, moment: datetime) -> bool:
        """Atomically claim (agent, nonce). False when already claimed (replay).

        The check-and-insert is one transaction: two concurrent replays of the
        same request cannot both win. Nonces older than the window are pruned
        on the same clock, and the table survives restart.
        """
        with self._lock:
            cutoff = _ts(moment) - NONCE_WINDOW_SECONDS
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM nonces WHERE seen_at <= ?", (cutoff,))
                self._conn.execute(
                    "INSERT INTO nonces (agent, nonce, seen_at) VALUES (?, ?, ?)",
                    (agent, nonce, _ts(moment)),
                )
                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError:
                self._conn.execute("ROLLBACK")
                return False
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            return True

    def _note_seen(self, agent: str, moment: datetime) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO presence (agent, last_seen) VALUES (?, ?)"
                " ON CONFLICT(agent) DO UPDATE SET last_seen = excluded.last_seen",
                (agent, _ts(moment)),
            )

    # -- mailbox accounting ----------------------------------------------

    def _mailbox_usage(self, recipient: str) -> tuple[int, int]:
        row = self._conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM mail WHERE recipient = ?",
            (recipient,),
        ).fetchone()
        return row[0], row[1]

    def _at_cap(self, recipient: str, extra_bytes: int = 0) -> bool:
        count, size = self._mailbox_usage(recipient)
        return count >= self.max_messages or size + extra_bytes > self.max_bytes

    # -- deposit ----------------------------------------------------------

    def deposit(
        self, envelope: Any, size: int, now: datetime | None = None
    ) -> tuple[str, str]:
        """Store one signed envelope. Returns ("accepted"|"duplicate", messageId).

        Raises :class:`_Refused` for every permanent deposit refusal and
        :class:`_OverCapacity` when the recipient's mailbox is at cap. The
        commit is fsynced before this returns, so a 202 means durable.
        """
        moment = now or datetime.now(timezone.utc)
        if not isinstance(envelope, dict):
            raise _Refused("envelope must be an object")
        sender = envelope.get("from")
        if not isinstance(sender, str) or not sender:
            raise _Refused("envelope has no sender")
        if sender == self.agent_id:
            raise _Refused("the hub is not an agent and deposits nothing")
        public_key = self._card_public_key(sender)
        if public_key is None:
            raise _Refused("unknown sender")
        # verify_envelope refuses an envelope past expiresAt as of *now* —
        # but HUB.md says an already-expired deposit is accepted (202) and
        # produces an expired frame. Verify as of sentAt, then apply the
        # hub's own expiry decision below.
        sent_at = _parse_iso(envelope.get("sentAt"))
        ok, _reason = verify_envelope(envelope, public_key, sent_at)
        if not ok:
            raise _Refused("envelope does not verify")
        recipients = envelope["to"]
        if not isinstance(recipients, list) or len(recipients) != 1:
            raise _Refused("one recipient only; fan-out is not in v1")
        recipient = recipients[0]
        if recipient not in self.cards or self._card_public_key(recipient) is None:
            raise _Refused("unknown recipient")
        message = envelope["message"]
        message_id = message["messageId"]
        context_id = message["contextId"]
        with self._lock:
            existing = self._conn.execute(
                "SELECT payload_json FROM mail WHERE recipient = ? AND sender = ?"
                " AND message_id = ? AND kind = 'envelope'",
                (recipient, sender, message_id),
            ).fetchone()
            if existing is not None:
                try:
                    stored = json.loads(existing[0])
                except ValueError:
                    stored = None
                if stored == envelope:
                    return "duplicate", message_id
                raise _Refused("messageId already used by that sender with a different body")
            if self._at_cap(recipient, size):
                raise _OverCapacity()
            expires = _parse_iso(envelope["expiresAt"])
            assert expires is not None  # verify_envelope already parsed it
            if expires <= moment:
                # Already expired at deposit: accepted, dropped immediately,
                # and the sender gets the same signed frame as from a sweep.
                self._queue_expired_frame(
                    sender, message_id, context_id, moment, _locked=True
                )
            else:
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    self._conn.execute(
                        "INSERT INTO mail (recipient, sender, message_id, kind,"
                        " payload_json, size, expires_at, inserted_at)"
                        " VALUES (?, ?, ?, 'envelope', ?, ?, ?, ?)",
                        (recipient, sender, message_id,
                         json.dumps(envelope, sort_keys=True), size,
                         _ts(expires), _ts(moment)),
                    )
                    self._conn.execute("COMMIT")
                except BaseException:
                    self._conn.execute("ROLLBACK")
                    raise
            self._note_seen(sender, moment)
            return "accepted", message_id

    # -- fetch / ack ------------------------------------------------------

    def fetch(
        self, agent: str, *, after: int = 0, limit: int = FETCH_DEFAULT_LIMIT,
        now: datetime | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """One FIFO page of the caller's mailbox, oldest first.

        Envelopes past ``expiresAt`` but not yet swept are skipped, never
        handed over — the sweep owns deletion and framing, fetch only refuses
        to deliver dead mail. ``next`` is the cursor for the following page,
        or null when this page is the last.
        """
        moment = now or datetime.now(timezone.utc)
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, payload_json FROM mail WHERE recipient = ?"
                " AND id > ? AND expires_at > ? ORDER BY id ASC LIMIT ?",
                (agent, after, _ts(moment), limit + 1),
            ).fetchall()
            page = rows[:limit]
            next_cursor = _encode_cursor(page[-1][0]) if len(rows) > limit else None
            return [json.loads(payload) for _id, payload in page], next_cursor

    def ack(self, agent: str, message_ids: list[str]) -> int:
        """Delete the caller's ids from the caller's mailbox; return how many.

        Scoped to the caller's own box: foreign ids are ignored rather than
        refused, and a duplicate ack is idempotent (second call returns 0).
        """
        with self._lock:
            deleted = 0
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for message_id in message_ids:
                    cursor = self._conn.execute(
                        "DELETE FROM mail WHERE recipient = ? AND message_id = ?",
                        (agent, message_id),
                    )
                    deleted += cursor.rowcount
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            return deleted

    # -- presence / health --------------------------------------------------

    def presence(self, target: str) -> tuple[bool, str | None]:
        """(online, lastSeen) for ``target``. Unknown agents answer offline
        with no timestamp — presence must not become a directory oracle."""
        moment = datetime.now(timezone.utc)
        with self._lock:
            row = self._conn.execute(
                "SELECT last_seen FROM presence WHERE agent = ?", (target,)
            ).fetchone()
        if row is None:
            return False, None
        last_seen = datetime.fromtimestamp(row[0], timezone.utc)
        online = (moment - last_seen).total_seconds() < PRESENCE_ONLINE_SECONDS
        return online, _iso(last_seen)

    def health(self, agent: str) -> tuple[int, int]:
        """The caller's own mailbox depth and dropped-frame count. Nothing else."""
        with self._lock:
            count, _size = self._mailbox_usage(agent)
            row = self._conn.execute(
                "SELECT count FROM dropped_frames WHERE owner = ?", (agent,)
            ).fetchone()
            return count, row[0] if row else 0

    # -- expiry -----------------------------------------------------------

    def sweep(self, now: datetime | None = None) -> int:
        """One expiry pass: drop past-``expiresAt`` mail, frame the senders.

        Returns how many envelopes expired. Frames past their own 72-hour TTL
        are dropped silently — no frame is ever made for a frame. A frame that
        cannot be queued because the sender's box is at cap is counted in
        ``dropped_frames`` and reported by that owner's health endpoint;
        nothing disappears silently.
        """
        moment = now or datetime.now(timezone.utc)
        expired = 0
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                rows = self._conn.execute(
                    "SELECT id, recipient, sender, message_id, kind,"
                    " payload_json FROM mail WHERE expires_at <= ?",
                    (_ts(moment),),
                ).fetchall()
                for row_id, recipient, sender, message_id, kind, payload in rows:
                    self._conn.execute("DELETE FROM mail WHERE id = ?", (row_id,))
                    if kind != "envelope":
                        continue
                    expired += 1
                    try:
                        context_id = json.loads(payload)["message"]["contextId"]
                    except (ValueError, KeyError, TypeError):
                        continue
                    self._queue_expired_frame(
                        sender, message_id, context_id, moment, _locked=True
                    )
                cutoff = _ts(moment) - NONCE_WINDOW_SECONDS
                self._conn.execute("DELETE FROM nonces WHERE seen_at <= ?", (cutoff,))
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            return expired

    def _queue_expired_frame(
        self,
        sender: str,
        message_id: str,
        context_id: str,
        moment: datetime,
        *,
        _locked: bool = False,
    ) -> bool:
        """Store a hub-signed ``expired`` frame in the sender's mailbox.

        Returns False when the sender's box is at cap: the drop is counted
        (and surfaced by health) instead of failing the sweep or the deposit
        that triggered it. Callers hold ``self._lock`` when ``_locked``.
        """
        frame = sign_expired_frame(
            self.identity, message_id=message_id, context_id=context_id,
            recipient_id=sender, now=moment,
        )
        raw = json.dumps(frame, sort_keys=True)
        if self._at_cap(sender, len(raw.encode("utf-8"))):
            log.warning(
                "hub could not queue expired frame for %s: mailbox at cap;"
                " messageId %s dropped from the frame queue",
                sender, message_id,
            )
            self._conn.execute(
                "INSERT INTO dropped_frames (owner, count, last_at) VALUES (?, 1, ?)"
                " ON CONFLICT(owner) DO UPDATE SET count = count + 1,"
                " last_at = excluded.last_at",
                (sender, _ts(moment)),
            )
            return False
        self._conn.execute(
            "INSERT OR IGNORE INTO mail (recipient, sender, message_id, kind,"
            " payload_json, size, expires_at, inserted_at)"
            " VALUES (?, ?, ?, 'frame', ?, ?, ?, ?)",
            (sender, self.agent_id, message_id, raw, len(raw.encode("utf-8")),
             _ts(moment + FRAME_TTL), _ts(moment)),
        )
        return True
