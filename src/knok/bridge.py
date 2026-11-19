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
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import identity as identity_mod
from . import policy as policy_mod
from .agentcard import verify_card
from .contacts import Contacts
from .envelope import sign, verify_envelope
from .gate import Gate, Threads
from .hub import verify_frame
from .hubclient import HubClient, HubError, HubRefused
from .identity import Identity, fingerprint
from .queue import Queue
from .rates import Rates

log = logging.getLogger("knok.bridge")

DEFAULT_POLL_SECONDS = 2.0
#: How many times one mailbox item may fail to verify before the bridge acknowledges it away.
#: Without a bound, a single unverifiable envelope sits at the head of the mailbox forever and the
#: mail behind it is never reached — the hub's 72-hour expiry is the backstop, not the mechanism.
MAX_HANDLE_ATTEMPTS = 5
#: How many refusal notices one sender may land in our ``notices.jsonl`` per hour. A notice is
#: handled before the gate (it *is* a gate answer), so it is not rate-limited by §9's message
#: counters; without a bound of its own a pinned correspondent could grow our log without limit.
MAX_REFUSAL_NOTICES_PER_HOUR = 100
#: The metadata key a refusal notice travels under. A2A fixes ``Message.kind`` to ``"message"``
#: and ``metadata`` is the one place it defines for extensions, so the notice rides there rather
#: than inventing a kind the validator (rightly) rejects.
NOTICE_KEY = "knok.notice"


def iso(moment: datetime) -> str:
    """The one timestamp format the wire and the logs both use."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def item_key(item: Any) -> str:
    """A stable id for a mailbox item, including one that is too broken to have a messageId."""
    if isinstance(item, dict):
        for candidate in (item.get("messageId"), (item.get("message") or {}).get("messageId")):
            if isinstance(candidate, str) and candidate:
                return candidate
    import hashlib

    return "sha256:" + hashlib.sha256(
        json.dumps(item, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:32]


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
        #: Per-process attempt counter for items that could not be verified. A restart grants a
        #: fresh allowance, which is the point: a registry that was briefly unreadable should
        #: recover, while a permanently bad item is still bounded by the hub's own TTL.
        self._attempts: dict[str, int] = {}
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

        counts = {"fetched": 0, "queued": 0, "refused": 0, "notices": 0, "unhandled": 0,
                  "dropped": 0}
        handled: list[str] = []
        for item in page.get("messages", []):
            counts["fetched"] += 1
            outcome, message_id = self._handle(item)
            if message_id is None:
                key = item_key(item)
                attempts = self._attempts.get(key, 0) + 1
                self._attempts[key] = attempts
                if attempts < MAX_HANDLE_ATTEMPTS:
                    counts["unhandled"] += 1
                    continue
                # Bounded and now exhausted: acknowledge it away so the mailbox can advance, and
                # leave a record. Re-offering it a sixth time only starves everything behind it.
                log.error("dropping an unhandleable item after %d attempts: %s", attempts, key)
                if not self._record_drop(item, key):
                    # The record is the only evidence this message ever existed. Without it the ack
                    # would erase the message and leave nothing behind, so the drop waits instead.
                    counts["unhandled"] += 1
                    continue
                del self._attempts[key]
                counts["dropped"] += 1
                handled.append(key)
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

        # A peer's answer to our own mailbox is not mail for the agent: it is a statement about a
        # message we sent, and it is handled here so it can never enter a thread or a gate decision.
        notice = (item["message"].get("metadata") or {}).get(NOTICE_KEY)
        if notice is not None:
            return self._handle_refusal_notice(item, sender, notice)

        decision = self.gate.decide(item)
        message_id = item["message"]["messageId"]
        if not decision.allowed:
            # Recorded as handled: the hub must stop offering it, or a 50-message page that is all
            # refusals never advances (HUB.md, "ack means handled").
            log.info("gate refused %s from %s: %s", message_id, sender, decision.reason)
            self._refuse(item, decision, message_id)
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

    # -- refusals: tell the sender, don't just ack the hub (#50) -----------

    def _refuse(self, item: dict[str, Any], decision, message_id: str) -> None:
        """Record a refusal locally, then answer the sender.

        The hub treats a refusal exactly like a delivery: our ack deletes the only copy, and the
        sender's ``knok send`` exited 0 long before this moment. So the fact that the message died
        has to be written down here and sent back here, or it is lost with the envelope.

        The local record comes first: if the notice cannot be deposited (peer mailbox full, hub
        down), the operator still has evidence of what was refused and under which rule.
        """
        sender = item.get("from")
        if not isinstance(sender, str):
            return
        context = (item.get("message") or {}).get("contextId")
        moment = datetime.now(timezone.utc)
        self._append_line(
            "refused.jsonl",
            {
                "at": iso(moment),
                "messageId": message_id,
                "contextId": context,
                "from": sender,
                "rule": decision.rule,
            },
            level="error",
        )
        # A blocked peer is exempt from the notice: blocking must look like nonexistence, so a
        # notice would confirm the identity is recognised and gated, and would distinguish blocked
        # from never-seen (the same uniform-refusal reasoning as the #42 denial). The local record
        # above is the only trace a blocked refusal leaves.
        if decision.rule == "blocked":
            return
        self._send_refusal_notice(sender, message_id, context, decision.rule, moment)

    def _send_refusal_notice(
        self, sender: str, message_id: str, context: str | None, rule: str, moment: datetime
    ) -> bool:
        """Deposit a signed notice to the sender of a message this bridge refused.

        Only ever addressed to a sender whose key the operator has already pinned in this agent's
        registry — a stranger never gets this far, because ``_handle`` cannot verify its signature
        and leaves the envelope at the hub. Telling a known correspondent that its own message
        failed leaks nothing about anyone else; the uniform 403 for strangers is untouched.
        Blocked senders never reach this method: ``_refuse`` exempts them, so blocking looks like
        nonexistence.

        The notice is an ordinary form-1 envelope carrying ``message.metadata["knok.notice"]``
        rather than a new ``kind``: A2A fixes ``Message.kind`` to ``"message"`` and ``metadata`` is
        the extension point it defines, so a validator on the far side keeps working unchanged.
        """
        notice: dict[str, Any] = {"kind": "refused", "messageId": message_id, "rule": rule}
        if isinstance(context, str) and context:
            notice["contextId"] = context
        unsigned: dict[str, Any] = {
            "envelopeVersion": 1,
            "seq": 0,
            # A fresh context: a notice is about a message, it is not a reply in its thread. Putting
            # it in the refused message's context would spend a reply expectation and could close it.
            "message": {
                "kind": "message",
                "messageId": f"r-{uuid.uuid4().hex}",
                "contextId": f"c-notice-{uuid.uuid4().hex}",
                "role": "agent",
                "parts": [
                    {"kind": "text", "text": f"knok: {rule} refused {message_id} before delivery"}
                ],
                "metadata": {NOTICE_KEY: notice},
            },
            "from": self.identity.agent_id,
            "to": [sender],
            "sentAt": iso(moment),
            "expiresAt": iso(moment + timedelta(hours=24)),
            "turn": {"expectsReply": False, "closesThread": False},
        }
        try:
            self.client.deposit(sign(unsigned, self.identity))
            return True
        except HubError as exc:
            # Not fatal and not retried here: the refusal already has a durable local record, and
            # retrying inside the poll would let one unreachable peer stall every other message.
            log.error("could not tell %s that %s was refused: %s", sender, message_id, exc)
            return False

    def _handle_refusal_notice(self, item: dict[str, Any], sender: str, notice: Any):
        """Record a peer's refusal of one of our messages, then let the hub drop it.

        This is the receiving half of #50: the sender learns, in its own ``notices.jsonl``, that
        its message was refused and under which rule — instead of waiting forever for a reply that
        cannot come.
        """
        message_id = item["message"]["messageId"]
        moment = datetime.now(timezone.utc)
        if not isinstance(notice, dict) or not isinstance(notice.get("messageId"), str):
            log.warning("ignoring a malformed refusal notice from %s", sender)
            return "refused", message_id
        if (
            self.rates.count("notice", sender, moment, timedelta(hours=1))
            >= MAX_REFUSAL_NOTICES_PER_HOUR
        ):
            # A pinned peer can still flood us: a notice is handled before the gate, so §9's
            # message counters never see it. Bound our own log rather than the sender's mailbox.
            log.error("too many refusal notices from %s; not recording %s", sender, message_id)
            return "refused", message_id
        frame = {
            "kind": "refused",
            "from": sender,
            "receivedAt": iso(moment),
            "messageId": notice["messageId"],
            "contextId": notice.get("contextId"),
            "rule": notice.get("rule"),
        }
        log.warning(
            "%s refused our message %s at its gate (%s)",
            sender,
            notice["messageId"],
            notice.get("rule"),
        )
        if not self._record_notice(frame):
            # The notice is the only evidence the message died. Without it on disk, leave the frame
            # at the hub and let the bounded attempt counter decide, rather than ack it away.
            return "unhandled", None
        self.rates.hit("notice", sender, moment, timedelta(hours=1))
        return "notices", message_id

    def _append_line(self, name: str, record: dict[str, Any], *, level: str = "warning") -> bool:
        """Append one fsynced JSON line to a state file. False (and logged) when it cannot be written."""
        path = self.state.directory / name
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return True
        except OSError as exc:
            log.log(getattr(logging, level.upper(), logging.WARNING),
                    "could not write %s: %s", name, exc)
            return False

    def _record_drop(self, item: Any, key: str) -> bool:
        """Write the drop record. False when it could not be written, so the caller does not ack.

        A dropped message is gone from the hub on the strength of this line being on disk. If the
        write fails, acking would destroy the only copy and leave no trace — the one outcome this
        whole path exists to avoid — so the caller leaves the item unacked and tries again.
        """
        path = self.state.directory / "dropped.jsonl"
        record = {"key": key, "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "item": item}
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return True
        except OSError as exc:
            log.error("could not record a dropped item %s; leaving it at the hub: %s", key, exc)
            return False

    def _record_notice(self, frame: dict[str, Any]) -> bool:
        """Keep notices where a human can see them; they are not messages and never enter a thread.

        Returns whether the frame is on disk. The caller confirms the notice with the queue only
        on ``True``, so a failed write leaves the queue free to offer it again.
        """
        path = self.state.directory / "notices.jsonl"
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(frame, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return True
        except OSError as exc:
            log.warning("could not record notice: %s", exc)
            return False

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
            kind = envelope.get("kind")
            if kind in {"gap", "late", "expired", "dead"}:
                # Record first, confirm second. A notice marked delivered before the frame is on
                # disk is lost to a crash in between, and the sender is never told its message
                # died — the failure this whole path exists to prevent. If the write fails, the
                # notice stays unconfirmed and is re-offered after its backoff.
                if self._record_notice(envelope):
                    notice_id = envelope.get("_noticeId")
                    if isinstance(notice_id, int):
                        self.queue.confirm_notice(notice_id)
                else:
                    log.error("could not record a %s notice; leaving it to be re-offered", kind)
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
