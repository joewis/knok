"""Direct bridge-to-bridge transport (SPEC §6, §9; issue #21).

One bridge per agent, loopback only, stdlib ``http.server``. This is Phase 1's exit
criterion made concrete: a signed envelope actually travels between two processes
(here, two bridges in one process on two loopback ports) and comes back acked.

Wire contract, ``POST /v1/envelope``:

1. Read the body with a hard 64 KiB cap (§9). Anything over the cap is refused
   without being read to the end, parsed, or verified.
2. Look up the sender's registered card and verify it against the registry
   (``agentcard.verify_card``), then ``verify_envelope()`` against the card's
   key. The card check runs first: a key the registry never published is not
   a sender, however well the envelope is signed.
3. ``Gate.decide()`` — the closed-by-default handshake, limits and thread rules.
4. ``Queue.put()`` — fsync before ack. The ack is built and sent only after
   ``put()`` returns, so an acked message is durable (§6, §10). A duplicate
   ``messageId`` is acked again, not delivered twice: at-least-once senders
   retransmit, and a retransmission is not a refusal.

Every refusal — bad signature, unknown card, stranger, malformed body, over-cap,
sealed (form 2, which has no ``message`` for the gate or queue to work on),
wrong recipient — returns the same status and the same body, ``REFUSED`` (§9:
a distinguishable refusal is an existence oracle). The handler never leaks
the reason, and never raises on hostile input.

The ack (§6) is a signed transport frame, never a ``Message``: the receiving
bridge signs it with its own identity, and the sender verifies it against the
recipient's registered card before treating the message as delivered.
"""

from __future__ import annotations

import base64
import http.client
import http.server
import json
import threading
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .agentcard import sign_card, verify_card
from .canonical import CanonicalisationError, canonical_bytes
from .contacts import REFUSED
from .envelope import verify_envelope
from .gate import Gate
from .identity import Identity, b64url_decode, public_key_from_b64, verify_signature
from .queue import Queue

#: §9 content cap: 64 KiB per message, no file transfer.
MAX_ENVELOPE_BYTES = 64 * 1024

#: The one refusal. Same status, same body, for every refusal kind (§9).
REFUSAL_STATUS = 403
REFUSAL_BODY = json.dumps({"error": REFUSED}, sort_keys=True).encode("ascii")

__all__ = [
    "MAX_ENVELOPE_BYTES",
    "REFUSAL_BODY",
    "REFUSAL_STATUS",
    "Bridge",
    "TransportRefused",
    "make_agent_card",
    "post_envelope",
    "registry_for",
    "sign_ack",
    "verify_ack",
]


class TransportRefused(RuntimeError):
    """The peer bridge refused delivery. Carries the shared refusal, nothing more."""

    def __init__(self, status: int, body: bytes):
        super().__init__(f"delivery refused: HTTP {status}")
        self.status = status
        self.body = body


def make_agent_card(identity: Identity, hub: str, url: str) -> dict[str, Any]:
    """Build and sign the agent's card (§5) for the local-pair registry.

    A fresh X25519 encryption key is generated per call; the signing key signs
    the card, so a substituted encryption key is detectable (§4). Cards are
    registry material: the caller hands the peer's signed card to its bridge.
    """
    raw = X25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    card = {
        "name": identity.agent_id.split("@")[0],
        "description": f"Knok bridge for {identity.agent_id}",
        "url": url,
        "version": "0.0.1",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [],
        "securitySchemes": [],
        "bridge": {
            "publicKey": identity.public_b64(),
            "encryptionKey": "x25519:" + base64.b64encode(raw).decode("ascii"),
            "sealedRequired": False,
            "contactPolicy": "closed",
            "hub": hub,
        },
    }
    return sign_card(card, identity)


def registry_for(*identities: Identity) -> dict[str, str]:
    """The registry ``verify_card`` expects: fingerprint -> public key (b64)."""
    return {identity.fingerprint: identity.public_b64() for identity in identities}


def sign_ack(
    identity: Identity,
    message_id: str,
    seq: int,
    context_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Sign the §6 ack frame: issued once the message is fsynced, never before."""
    moment = now or datetime.now(timezone.utc)
    frame = {
        "kind": "ack",
        "messageId": message_id,
        "seq": seq,
        "contextId": context_id,
        "ackedAt": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "from": identity.agent_id,
    }
    signed = dict(frame)
    signed["signature"] = identity.sign(canonical_bytes(frame))
    return signed


def verify_ack(ack: Any, public_key) -> bool:
    """Verify an ack frame against the acking bridge's key. Never raises."""
    if not isinstance(ack, dict) or ack.get("kind") != "ack":
        return False
    for field in ("messageId", "contextId", "ackedAt", "from"):
        if not isinstance(ack.get(field), str) or not ack[field]:
            return False
    seq = ack.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        return False
    signature = ack.get("signature")
    if not isinstance(signature, str):
        return False
    body = {key: value for key, value in ack.items() if key != "signature"}
    try:
        payload = canonical_bytes(body)
    except (CanonicalisationError, Exception):
        return False
    return verify_signature(public_key, payload, signature)


def post_envelope(url: str, raw: bytes, timeout: float = 10.0) -> tuple[int, bytes]:
    """POST raw bytes to a bridge's ``/v1/envelope``. Returns (status, body).

    This is the unadorned client the proofs use: it sends exactly what it is
    given, so a refusal can be observed rather than asserted.
    """
    parsed = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    try:
        conn.request(
            "POST", "/v1/envelope", body=raw,
            headers={"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # one request per connection; no keep-alive state
    server_version = "KnokBridge/0.1"

    def log_message(self, *args: object) -> None:  # keep demo/test output clean
        pass

    # -- helpers ---------------------------------------------------------

    def _refuse(self) -> None:
        self._send(REFUSAL_STATUS, REFUSAL_BODY)

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    # -- routes ----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - http.server names the method
        if urllib.parse.urlparse(self.path).path != "/v1/health":
            self._send(404, b'{"error":"not found"}')
            return
        bridge: Bridge = self.server.bridge  # type: ignore[attr-defined]
        body = json.dumps(
            {
                "status": "ok",
                "agent_id": bridge.agent_id,
                "queue_depth": bridge.queue.depth(),
            },
            sort_keys=True,
        ).encode("ascii")
        self._send(200, body)

    def do_POST(self) -> None:  # noqa: N802 - http.server names the method
        if urllib.parse.urlparse(self.path).path != "/v1/envelope":
            self._send(404, b'{"error":"not found"}')
            return
        bridge: Bridge = self.server.bridge  # type: ignore[attr-defined]
        length = self.headers.get("Content-Length")
        try:
            size = int(length) if length is not None else -1
        except ValueError:
            size = -1
        if size < 0 or size > MAX_ENVELOPE_BYTES:
            # Over-cap (or no usable length): refuse without reading the body
            # to the end. A stranger must not be able to make the bridge do
            # unbounded work. Drain at most one byte past the cap first, so a
            # client that sent just over the cap still receives the refusal
            # instead of a reset mid-send.
            if size > MAX_ENVELOPE_BYTES:
                self.rfile.read(MAX_ENVELOPE_BYTES + 1)
            self._refuse()
            return
        raw = self.rfile.read(size)
        if len(raw) != size:
            self._refuse()
            return
        try:
            envelope = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self._refuse()
            return
        # deliver() is written not to raise, but if it ever does — a card whose
        # ``bridge`` object is the wrong shape, a sqlite error under load —
        # the exception must not escape the handler: a 500 or a dropped
        # connection is distinguishable from every other refusal (§9).
        try:
            ack = bridge.deliver(envelope)
        except Exception:
            self._refuse()
            return
        if ack is None:
            self._refuse()
            return
        self._send(200, json.dumps(ack, sort_keys=True).encode("ascii"))


class Bridge:
    """One agent's bridge: its queue, its gate, its keys, one loopback port.

    ``cards`` maps every sender this bridge will hear from to that sender's
    signed Agent Card JWS; ``registry`` maps fingerprint -> public key (b64)
    and is the only trust root for those cards (§4: no trust-on-first-use).
    """

    def __init__(
        self,
        *,
        identity: Identity,
        queue: Queue,
        gate: Gate,
        cards: dict[str, dict[str, Any]],
        registry: dict[str, str],
        host: str = "127.0.0.1",
        port: int = 0,
    ):
        self.identity = identity
        self.agent_id = identity.agent_id
        self.queue = queue
        self.gate = gate
        self.cards = cards
        self.registry = registry
        self.host = host
        self.port = port
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- serving ---------------------------------------------------------

    @property
    def url(self) -> str:
        port = self._server.server_address[1] if self._server else self.port
        return f"http://{self.host}:{port}"

    def start(self) -> "Bridge":
        server = http.server.ThreadingHTTPServer((self.host, self.port), _Handler)
        server.daemon_threads = True
        server.bridge = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name=f"knok-{self.agent_id}", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "Bridge":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- delivery: verify, gate, durable put, then ack -------------------

    def deliver(self, envelope: Any) -> dict[str, Any] | None:
        """Handle one received envelope. Returns the signed ack, or None to refuse.

        Never raises: any failure is the same refusal. The ack is built only
        after ``Queue.put()`` returns, so an acked message is fsynced (§6).
        """
        if not isinstance(envelope, dict):
            return None
        sender = envelope.get("from")
        if not isinstance(sender, str) or not sender:
            return None
        card = self.cards.get(sender)
        if card is None:
            return None  # no registered card for this sender: not a sender
        ok, _reason = verify_card(card, self.registry, expected_agent_id=sender)
        if not ok:
            return None
        try:
            card_body = json.loads(b64url_decode(card["payload"]))
            public_key = public_key_from_b64(card_body["bridge"]["publicKey"])
        except Exception:
            return None
        ok, _reason = verify_envelope(envelope, public_key)
        if not ok:
            return None
        decision = self.gate.decide(envelope)
        if not decision.allowed:
            return None
        try:
            self.queue.put(envelope)
        except ValueError:
            return None
        # put() returned: the message is fsynced. Only now may the ack go out.
        message = envelope["message"]
        return sign_ack(
            self.identity,
            message["messageId"],
            envelope["seq"],
            message["contextId"],
        )

    # -- sending ---------------------------------------------------------

    def send(self, peer_url: str, envelope: dict[str, Any]) -> dict[str, Any]:
        """Send an envelope; return the verified ack. Raises on refusal or bad ack.

        The reply credit (``Threads.note_sent``) is recorded only after the
        peer's ack verifies: a refused message owes no reply, and a forged
        ack must not open the thread.
        """
        status, raw = post_envelope(peer_url, json.dumps(envelope).encode("ascii"))
        if status != 200:
            raise TransportRefused(status, raw)
        try:
            ack = json.loads(raw)
        except ValueError as exc:
            raise RuntimeError("peer returned an unparsable ack") from exc
        recipient = envelope["to"][0]
        card = self.cards.get(recipient)
        if card is None:
            raise RuntimeError(f"no registered card for {recipient}; cannot verify ack")
        try:
            card_body = json.loads(b64url_decode(card["payload"]))
            public_key = public_key_from_b64(card_body["bridge"]["publicKey"])
        except Exception as exc:
            raise RuntimeError("recipient card is malformed; cannot verify ack") from exc
        if not verify_ack(ack, public_key) or ack.get("messageId") != envelope["message"]["messageId"]:
            raise RuntimeError("peer ack does not verify; message not treated as delivered")
        message = envelope["message"]
        self.gate.threads.note_sent(
            message["contextId"],
            envelope["turn"]["expectsReply"],
            envelope["turn"]["closesThread"],
            datetime.now(timezone.utc),
        )
        return ack
