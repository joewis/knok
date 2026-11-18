"""The bridge: one agent's agent-side loop against a hub.

The bridge owns nothing but its own state — key, policy, queue — and polls a hub for mail addressed
to it. The order per message is the whole contract in one line:

    verify the sender's signature -> decide at the gate -> queue durably -> **then** ack the hub

Acking earlier would let the hub delete a message the bridge never wrote down, turning HUB.md's
at-least-once into at-most-once. ``Queue.put`` returns only after an fsynced commit for exactly this
reason, so the ack below it cannot run first.

The bridge does not interpret a body, does not accept a message for another agent (the queue refuses
it), and does not trust a transport frame unless the hub signed it.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import identity as identity_mod
from . import policy as policy_mod
from .agentcard import verify_card
from .contacts import Contacts
from .envelope import verify_envelope
from .gate import Gate, Threads
from .hub import verify_frame
from .hubclient import HubClient, HubError, HubRefused
from .identity import Identity, fingerprint
from .queue import Queue
from .rates import Rates

log = logging.getLogger("knok.bridge")

DEFAULT_POLL_SECONDS = 2.0


@dataclass
class BridgeState:
    """Where an agent keeps everything it owns. No two of these share a directory."""

    agent_id: str
    directory: Path
    hub_url: str
    registry: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def key_path(self) -> Path:
        return self.directory / "identity.key"

    @property
    def policy_path(self) -> Path:
        return self.directory / "policy.json"


def load_cards(directory: str | Path) -> dict[str, dict[str, Any]]:
    """Load the operator's registry: one signed card per file, keyed by agent id.

    The directory is the trust anchor in Phase 2 (HUB.md: no dynamic registration), so a card is
    checked for internal consistency — its JWS must verify under the key it itself carries — rather
    than against a separate root. A card that fails is dropped, not fatal: one broken file must not
    stop an agent from receiving mail from everyone else.
    """
    cards: dict[str, dict[str, Any]] = {}
    for path in sorted(Path(directory).glob("*.json")):
        try:
            document = json.loads(path.read_text())
        except (OSError, ValueError):
            log.warning("registry: %s is not readable json, ignoring", path)
            continue
        body = card_body(document)
        if body is None:
            log.warning("registry: %s does not verify, ignoring", path)
            continue
        agent_id = body.get("bridge", {}).get("agent") or path.stem
        cards[agent_id] = body
    return cards


def card_body(document: Any) -> dict[str, Any] | None:
    """Decode and self-verify a flattened JWS card. None when it does not verify."""
    if not isinstance(document, dict) or "payload" not in document:
        return None
    try:
        from .identity import b64url_decode

        body = json.loads(b64url_decode(document["payload"]))
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    public_key = body.get("bridge", {}).get("publicKey")
    if not isinstance(public_key, str):
        return None
    registry = {fingerprint_key(public_key): public_key}
    try:
        verify_card(document, registry)
    except Exception:
        return None
    return body


def fingerprint_key(public_b64: str) -> str:
    """The fingerprint a registry maps to a public key (SHA256 of the raw key, base64url)."""
    from .identity import public_key_from_b64

    return fingerprint(public_key_from_b64(public_b64))


class Bridge:
    """One agent, one queue, one hub."""

    def __init__(
        self,
        state: BridgeState,
        *,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        batch: int = 50,
        deliver: bool = False,
        clock=time.monotonic,
    ):
        self.state = state
        self.batch = batch
        # ``deliver`` makes this bridge the application as well as the transport: it drains the
        # queue into ``inbox.jsonl`` and acks each message. Off by default, because an embedded
        # bridge leaves delivery to whoever owns the queue (Hermes, a test, an agent runtime).
        self.deliver = deliver
        self.poll_seconds = poll_seconds
        self._clock = clock

        state.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(state.directory, 0o700)

        own_card = state.registry.get(state.agent_id)
        if own_card is None:
            raise ValueError(f"no registered card for {state.agent_id}")
        # The binding comes from the registry, not the PEM: the card's public key is the only
        # statement of which key belongs to this id, so its fingerprint is what the PEM must match.
        self.identity = identity_mod.load(
            state.agent_id,
            state.key_path,
            fingerprint_key(own_card["bridge"]["publicKey"]),
        )

        self.queue = Queue(state.directory / "queue.db", state.agent_id)
        self.rates = Rates(state.directory / "rates.db")
        self.contacts = Contacts(state.directory / "contacts.db", rates=self.rates)
        self.threads = Threads(state.directory / "threads.db")
        self.policy = policy_mod.load(state.policy_path)
        if self.policy.agent_id != state.agent_id:
            raise ValueError(
                f"policy is for {self.policy.agent_id}, not {state.agent_id}"
            )
        self.gate = Gate(self.policy, self.contacts, self.threads, self.rates)
        self.client = HubClient(state.hub_url, self.identity)

    # -- helpers ----------------------------------------------------------

    def close(self) -> None:
        for closable in (self.queue, self.contacts, self.threads, self.rates):
            try:
                closable.close()
            except Exception:  # a close must never mask the reason we are closing
                pass

    def __enter__(self) -> "Bridge":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def public_key_of(self, agent_id: str):
        card = self.state.registry.get(agent_id)
        if card is None:
            return None
        from .identity import public_key_from_b64

        try:
            return public_key_from_b64(card["bridge"]["publicKey"])
        except Exception:
            return None

    # -- the loop ---------------------------------------------------------

    def poll_once(self) -> dict[str, int]:
        """Fetch one page, handle it in order, ack what was handled.

        Returns counts. A message counts as handled when it was either queued durably or refused at
        the gate; a message that could not be handled at all (unverifiable sender, unknown card) is
        left unacked so the hub offers it again, because the alternative is silently dropping mail.
        """
        try:
            page = self.client.fetch(limit=self.batch)
        except HubError as exc:
            log.warning("fetch failed: %s", exc)
            return {"fetched": 0, "queued": 0, "refused": 0, "notices": 0, "unhandled": 1}

        counts = {"fetched": 0, "queued": 0, "refused": 0, "notices": 0, "unhandled": 0}
        handled: list[str] = []
        for item in page.get("messages", []):
            counts["fetched"] += 1
            outcome, message_id = self._handle(item)
            if message_id is None:
                counts["unhandled"] += 1
                continue
            counts[outcome] += 1
            handled.append(message_id)

        if handled:
            try:
                self.client.ack(handled)
            except HubError as exc:
                # Not fatal: the hub will offer these again and the queue dedupes them.
                log.warning("ack failed (%d ids): %s", len(handled), exc)

        if self.deliver:
            counts["delivered"] = self.drain()
        return counts

    def _handle(self, item: Any) -> tuple[str, str | None]:
        """Handle one mailbox item. Returns (outcome, messageId-or-None)."""
        if not isinstance(item, dict):
            return "unhandled", None

        if item.get("kind") in {"expired", "dead"}:
            return self._handle_frame(item)

        sender = item.get("from")
        if not isinstance(sender, str):
            return "unhandled", None
        public_key = self.public_key_of(sender)
        if public_key is None:
            log.warning("no registered card for sender %s; leaving the message at the hub", sender)
            return "unhandled", None
        ok, reason = verify_envelope(item, public_key)
        if not ok:
            log.warning("refused an unverifiable envelope from %s: %s", sender, reason)
            return "unhandled", None

        decision = self.gate.decide(item)
        message_id = item["message"]["messageId"]
        if not decision.allowed:
            # Recorded as handled: the hub must stop offering it, or a 50-message page that is all
            # refusals never advances (HUB.md, "ack means handled").
            log.info("gate refused %s from %s: %s", message_id, sender, decision.reason)
            return "refused", message_id

        result = self.queue.put(item)
        return ("queued" if result == "accepted" else "queued"), message_id

    def _handle_frame(self, frame: dict[str, Any]) -> tuple[str, str | None]:
        hub_card = self.state.registry.get(frame.get("from", ""))
        if hub_card is None:
            return "unhandled", None
        from .identity import public_key_from_b64

        if not verify_frame(frame, public_key_from_b64(hub_card["bridge"]["publicKey"])):
            log.warning("dropped a transport frame that is not hub-signed: %r", frame.get("kind"))
            return "unhandled", None
        message_id = frame.get("messageId")
        log.info(
            "notice: %s expired at %s (context %s)",
            message_id,
            frame.get("expiredAt"),
            frame.get("contextId"),
        )
        self._record_notice(frame)
        return "notices", message_id if isinstance(message_id, str) else None

    def _record_notice(self, frame: dict[str, Any]) -> None:
        """Keep notices where a human can see them; they are not messages and never enter a thread."""
        path = self.state.directory / "notices.jsonl"
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(frame, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            log.warning("could not record notice: %s", exc)

    def drain(self, limit: int = 50) -> int:
        """Hand queued messages to the application, then ack them out of the queue.

        The write to ``inbox.jsonl`` is fsynced before the queue ack, for the same reason the hub
        ack waits for the queue: an ack that outruns the write loses the message from both sides.
        """
        delivered = 0
        for _ in range(limit):
            envelope = self.queue.get()
            if envelope is None:
                break
            if envelope.get("kind") in {"gap", "expired", "dead"}:
                self._record_notice(envelope)
                continue
            try:
                self._append_inbox(envelope)
            except OSError as exc:
                log.error("could not write inbox; leaving the message queued: %s", exc)
                break
            self.queue.ack(envelope["message"]["messageId"])
            delivered += 1
        return delivered

    def _append_inbox(self, envelope: dict[str, Any]) -> None:
        path = self.state.directory / "inbox.jsonl"
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(envelope, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def run_forever(self, stop=None) -> None:
        """Poll until asked to stop. Jitter keeps ten bridges from landing on the same tick."""
        log.info("bridge %s polling %s", self.state.agent_id, self.state.hub_url)
        while True:
            if stop is not None and stop.is_set():
                return
            try:
                counts = self.poll_once()
                if counts["fetched"]:
                    log.info("poll: %s", counts)
            except Exception:  # a bad page must not kill the agent's ability to receive
                log.exception("poll failed; continuing")
            delay = self.poll_seconds * random.uniform(0.8, 1.2)
            if stop is not None:
                if stop.wait(delay):
                    return
            else:
                time.sleep(delay)
