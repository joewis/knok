"""The bridge: one agent's agent-side loop against a hub.

The bridge owns nothing but its own state — key, policy, queue — and polls a hub for mail addressed
to it. The order per message is the whole contract in one line:

    verify the sender's signature -> decide at the gate -> queue durably -> **then** ack the hub

Acking earlier would let the hub delete a message the bridge never wrote down, turning HUB.md's
at-least-once into at-most-once. ``Queue.put`` returns only after an fsynced commit for exactly this
reason, so the ack below it cannot run first.

The bridge does not interpret a body, does not accept a message for another agent (the queue refuses
it), and does not trust a transport frame unless the hub signed it.

Nothing the bridge reads once may stay read once. The pinned cards are re-read when the directory
changes, because a peer that a restart would admit is a peer that is silently dropped until the
restart happens (#54). ``policy.json`` fails the same way one layer up (#52); its reload is a
separate change, and this one sits where that one will.
"""

from __future__ import annotations

import json
import logging
import os
import random
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import identity as identity_mod
from . import policy as policy_mod
from .agentcard import CardTimeError, card_agent_id, card_valid_until, verify_card
from .contacts import Contacts
from .envelope import sent_at, sign, verify_envelope
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

#: Where those notices are written, in the sender's own state directory: a peer's refusal of one
#: of our messages, or the hub's ``expired``/``dead`` frame. The only record of a failure that
#: happened after ``knok send`` had already exited 0, and what ``knok notices`` reads.
NOTICES = "notices.jsonl"


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
    #: Where ``registry`` came from, when it came from a directory at all. The bridge re-reads it
    #: when a card is added or removed, and cannot do that from the dict alone — so a state built
    #: with an in-memory registry (a test, an embedded bridge) simply never reloads.
    registry_dir: Path | None = None

    @property
    def key_path(self) -> Path:
        return self.directory / "identity.key"

    @property
    def policy_path(self) -> Path:
        return self.directory / "policy.json"


def load_cards(directory: str | Path) -> dict[str, dict[str, Any]]:
    """Load the operator's registry: one signed card per file, keyed by the id the card claims.

    The directory is the trust anchor in Phase 2 (HUB.md: no dynamic registration), so a card is
    checked for internal consistency — its JWS must verify under the key it itself carries — rather
    than against a separate root. A card that fails is dropped, not fatal: one broken file must not
    stop an agent from receiving mail from everyone else.

    The key is ``name@hub`` **from the signed body**, not the file name. The body is the only thing
    the signature covers, so it is the only thing that may grant a name authority; a file named
    ``mallory@…`` holding a card that claims ``carl@…`` pins carl, and pins nothing under mallory
    (#62). A card that names no agent is dropped rather than pinned under whatever its file is
    called — a key with no id in its own signature is a key nobody signed for.
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
        agent_id = card_agent_id(body)
        if agent_id is None:
            log.warning("registry: %s names no agent (name@hub), ignoring", path)
            continue
        if path.stem != agent_id:
            # Not fatal — the signed body wins — but this is an operator mistake worth seeing,
            # because the file no longer says who it is about.
            log.warning("registry: %s holds the card for %s", path, agent_id)
        cards[agent_id] = body
    return cards


def card_body(document: Any) -> dict[str, Any] | None:
    """Decode and self-verify a flattened JWS card. None when it does not verify.

    ``None`` is the only answer for anything that is not a card this process may trust, and there
    are more ways to fail that test than a bad signature: a body that will not decode, a public key
    that will not parse, and a signature that does not verify all mean the same thing to the caller,
    whose only use for the body is as a pinned key. Nothing in here raises on bad input —
    ``load_cards`` runs it over a whole directory, and one unreadable file must not take the trust
    anchor, and with it the bridge, down.
    """
    if not isinstance(document, dict) or "payload" not in document:
        return None
    try:
        from .identity import b64url_decode

        body = json.loads(b64url_decode(document["payload"]))
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    bridge = body.get("bridge")
    public_key = bridge.get("publicKey") if isinstance(bridge, dict) else None
    if not isinstance(public_key, str):
        return None
    try:
        registry = {fingerprint_key(public_key): public_key}
    except Exception:
        # Fingerprinting the key is what has to succeed before ``verify_card`` can be asked, and it
        # raises on a key that is not a key. That is the same answer, and it is logged because a
        # silent drop in the trust anchor is how the bug below survived for as long as it did.
        log.warning("registry: card carries a public key that is not a key: %r", public_key[:64])
        return None
    ok, reason = verify_card(document, registry)
    if not ok:
        # ``verify_card`` *returns* its verdict; it does not raise on a bad signature, and never
        # did. Discarding that verdict — a bare call inside a ``try`` — accepted every document
        # whose payload merely decoded, so a mangled signature or a swapped body still became a
        # pinned key (#59). The docstring above has always promised this check; this is it.
        log.warning("registry: card does not verify: %s", reason)
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
        # Thread state shares the queue's file on purpose: the gate's decrement commits inside the
        # queue's insert transaction, so neither exists without the other (#69).
        self.threads = Threads(state.directory / "queue.db")
        self.policy = policy_mod.load(state.policy_path)
        if self.policy.agent_id != state.agent_id:
            raise ValueError(
                f"policy is for {self.policy.agent_id}, not {state.agent_id}"
            )
        self.gate = Gate(self.policy, self.contacts, self.threads, self.rates)
        self.client = HubClient(state.hub_url, self.identity)
        #: The file identity (mtime, size, inode) of the policy the running gate was built from.
        #: ``stat`` is the cheap way to notice an edit: the daemon must not pay a parse per poll, and
        #: a parse per *message* would still race a mid-decision rewrite.
        self._policy_stamp = self._policy_file_stamp()
        #: The set of card files the registry in force was loaded from, by (name, mtime, size, inode).
        #: The directory's own mtime is not enough: rewriting an existing card changes the file, not
        #: the directory, and on a coarse clock a rewrite can land inside the same timestamp tick.
        self._registry_stamp: tuple[tuple[str, int, int, int], ...] | None = (
            self._registry_dir_stamp()
        )

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

    def public_key_of(self, agent_id: str, at: datetime | None = None):
        """The pinned key for ``agent_id``, or None when its card does not account for ``at``.

        ``load_cards`` verified each card once, when this process started. That verdict does not
        age with the clock: a card carrying ``validUntil`` was trusted forever by whoever loaded
        it (#62). So the expiry is re-read here, from the body that is pinned — the field is
        inside the signed payload, which is what load-time verification checked, so the answer
        cannot be moved without the key that signed the card.

        ``at`` is the instant asked about, and the loop passes the envelope's ``sentAt``
        (decision 0002: ask about the key when the message was signed, not when it arrived). A
        card with no ``validUntil`` — every card in the current live registry — states no limit
        and answers exactly as it did before.

        What this does *not* do is re-verify the signature per message, or consult a ``Registry``
        for revocation: the pinned entry is a body, not a document, and the registry here is the
        legacy dict. Both are named on #62; this answers the expiry question only, which is the
        one the field actually makes. The id binding *is* checked, at adoption: ``load_cards``
        keys each body by the ``name@hub`` the body itself claims, so a key is only ever pinned
        under a name it signed for.
        """
        card = self.state.registry.get(agent_id)
        if card is None:
            return None
        instant = at or datetime.now(timezone.utc)
        try:
            valid_until = card_valid_until(card)
        except CardTimeError as exc:
            log.warning("card for %s states a validUntil that cannot be read (%s); not trusting it",
                        agent_id, exc)
            return None
        if valid_until is not None and instant >= valid_until:
            log.warning(
                "card for %s expired at %s; not trusting it at %s",
                agent_id,
                valid_until.isoformat(),
                instant.isoformat(),
            )
            return None
        from .identity import public_key_from_b64

        try:
            return public_key_from_b64(card["bridge"]["publicKey"])
        except Exception:
            return None

    # -- the loop ---------------------------------------------------------

    def _policy_file_stamp(self) -> tuple[int, int, int] | None:
        """Identity of the policy file on disk, or ``None`` when it is gone.

        ``st_mtime_ns`` alone can miss a rewrite that lands inside the same timestamp tick on a
        coarse filesystem, so size and inode ride along: an editor that writes-then-renames changes
        the inode even when the size does not.
        """
        try:
            info = os.stat(self.state.policy_path)
        except OSError:
            return None
        return (info.st_mtime_ns, info.st_size, info.st_ino)

    def reload_policy_if_changed(self) -> bool:
        """Adopt a changed ``policy.json`` without a restart (#52). True when a new policy is live.

        Called at the top of every poll, so an edit takes effect on the *next* message rather than
        the next process lifetime — revocation that needs a restart is not revocation.

        A reload never throws the store away: ``Contacts``, ``Threads`` and ``Rates`` are DB-backed
        and outlive any one policy, so only the ``Gate`` is rebuilt, around the same three objects.
        A file that does not parse, names another agent, or is unreadable leaves the policy already
        in force untouched and says so at ERROR — a policy bug must not quietly open a gate, and it
        must not crash the bridge either, or a typo becomes an outage.
        """
        stamp = self._policy_file_stamp()
        if stamp is None:
            if self._policy_stamp is not None:
                log.error(
                    "policy %s is gone or unreadable; keeping the policy in force",
                    self.state.policy_path,
                )
                self._policy_stamp = stamp
            return False
        if stamp == self._policy_stamp:
            return False
        # Remember the stamp before parsing: a file that fails to load must be reported once, not
        # re-read and re-logged every poll until someone fixes it.
        self._policy_stamp = stamp
        try:
            policy = policy_mod.load(self.state.policy_path)
        except policy_mod.PolicyError as exc:
            log.error("policy reload failed, keeping the policy in force: %s", exc)
            return False
        if policy.agent_id != self.state.agent_id:
            log.error(
                "policy reload refused: the file is for %s, this bridge is %s",
                policy.agent_id,
                self.state.agent_id,
            )
            return False
        if policy == self.policy:
            return False

        added = policy.allow - self.policy.allow
        removed = self.policy.allow - policy.allow
        self.policy = policy
        self.gate = Gate(policy, self.contacts, self.threads, self.rates)
        log.info(
            "policy reloaded: allow +%d -%d, %d blocked, contact_policy=%s",
            len(added),
            len(removed),
            len(policy.block),
            policy.contact_policy,
        )
        return True

    def _registry_dir_stamp(self) -> tuple[tuple[str, int, int, int], ...] | None:
        """Identity of the registry directory's card files, or ``None`` when it is unreadable.

        Every card is stamped, not just the directory: ``provision.py`` rewrites one file at a time,
        so a new peer changes the set while the directory's own mtime may already have settled. A
        removal changes the set too, which is the half that makes a *revoked* card stop being trusted.
        """
        if self.state.registry_dir is None:
            return None
        try:
            paths = sorted(Path(self.state.registry_dir).glob("*.json"))
        except OSError:
            return None
        stamps: list[tuple[str, int, int, int]] = []
        for path in paths:
            try:
                info = path.stat()
            except OSError:
                # A file that vanished between the glob and the stat is simply not in this stamp;
                # the next poll will not see it either, and the set is what is compared.
                continue
            stamps.append((path.name, info.st_mtime_ns, info.st_size, info.st_ino))
        return tuple(stamps)

    def reload_registry_if_changed(self) -> bool:
        """Adopt a card added, changed or removed since the last poll (#54). True when swapped.

        The policy reload (#52) fixes the *gate*; this fixes the trust anchor behind it. A peer
        provisioned after this bridge started has no pinned card, so ``_handle`` cannot verify its
        signature, leaves the envelope at the hub, and after the bounded attempt counter it is dropped
        — a silent drop, which is the #48 class one layer down.

        Two things make this a security change rather than a plumbing one, and both fail closed by
        keeping the registry already in force:

        * **A card removed from the directory stops being trusted.** Otherwise revocation of a *key*,
          as opposed to a peer, would still need a restart — the same bug one layer down.
        * **A directory that yields no cards at all is refused.** An empty registry is not "trust
          nobody": it is every correspondent suddenly unverifiable, i.e. silently dropped mail, and
          the usual cause is a provisioning step caught mid-rewrite. ``load_cards`` already drops a
          card that fails its own signature check, so a single bad edit narrows the registry rather
          than emptying it — that case still swaps, because it is a real statement about that card.
        """
        if self.state.registry_dir is None:
            return False
        stamp = self._registry_dir_stamp()
        if stamp is None or stamp == self._registry_stamp:
            return False
        # Remembered before loading, so a directory that cannot be loaded is reported once instead
        # of re-read on every poll until someone fixes it.
        self._registry_stamp = stamp
        cards = load_cards(self.state.registry_dir)
        if not cards:
            log.error(
                "registry reload refused: %s yields no cards; keeping the %d already pinned",
                self.state.registry_dir,
                len(self.state.registry),
            )
            return False
        if self.state.agent_id not in cards:
            log.error(
                "registry reload refused: %s has no card for this agent (%s); keeping the registry "
                "in force",
                self.state.registry_dir,
                self.state.agent_id,
            )
            return False
        if cards == self.state.registry:
            return False

        added = sorted(cards.keys() - self.state.registry.keys())
        removed = sorted(self.state.registry.keys() - cards.keys())
        # One assignment: ``public_key_of`` and ``_handle`` read the dict per message, so a message
        # is verified against one registry or the other, never half of each.
        self.state.registry = cards
        log.info(
            "registry reloaded: +%d -%d, %d pinned%s%s",
            len(added),
            len(removed),
            len(cards),
            f"; added {', '.join(added)}" if added else "",
            f"; removed {', '.join(removed)}" if removed else "",
        )
        return True

    def poll_once(self) -> dict[str, int]:
        """Fetch one page, handle it in order, ack what was handled.

        Returns counts. A message counts as handled when it was either queued durably or refused at
        the gate; a message that could not be handled at all (unverifiable sender, unknown card) is
        left unacked so the hub offers it again, because the alternative is silently dropping mail.
        """
        self.reload_policy_if_changed()
        self.reload_registry_if_changed()
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
        # The card is asked about as of the envelope's own ``sentAt``, matching transport and the
        # hub (decision 0002): a card that lapsed this morning must still account for a message
        # signed yesterday, and must not account for one signed after it lapsed.
        public_key = self.public_key_of(sender, at=sent_at(item))
        if public_key is None:
            log.warning("no trusted card for sender %s; leaving the message at the hub", sender)
            return "unhandled", None
        ok, reason = verify_envelope(item, public_key)
        if not ok:
            log.warning("refused an unverifiable envelope from %s: %s", sender, reason)
            return "unhandled", None

        message = item.get("message")
        if not isinstance(message, dict):
            # Sealed (form 2): its contextId is inside the sealed body, so neither the gate nor the
            # queue can order it before decryption (and where that decryption happens is #70's
            # open decision). Left unhandled rather than guessed at.
            log.warning("no form 1 message in an item from %s; leaving it at the hub", sender)
            return "unhandled", None

        # A peer's answer to our own mailbox is not mail for the agent: it is a statement about a
        # message we sent, and it is handled here so it can never enter a thread or a gate decision.
        notice = (message.get("metadata") or {}).get(NOTICE_KEY)
        if notice is not None:
            return self._handle_refusal_notice(item, sender, notice)

        # The message id is trusted for dedupe only after the signature and the card checked out
        # above: anyone can write an id into an envelope, so the id alone must never be able to
        # suppress a message.
        message_id = message.get("messageId")
        if not isinstance(message_id, str) or not message_id:
            return "unhandled", None

        # A message already accepted is acknowledged and skipped *before* the gate (#69): the
        # durable insert and the thread decrement committed together the first time, so a retry
        # after a lost ack must not decrement the thread a second time.
        if self.queue.seen(message_id):
            log.info("re-offered message %s is already queued; acking without gate work", message_id)
            return "queued", message_id

        decision = self.gate.decide(item)
        if not decision.allowed:
            # Recorded as handled: the hub must stop offering it, or a 50-message page that is all
            # refusals never advances (HUB.md, "ack means handled").
            log.info("gate refused %s from %s: %s", message_id, sender, decision.reason)
            self._refuse(item, decision, message_id)
            return "refused", message_id

        try:
            # The gate's answer is applied here, by the queue, in the insert's transaction: a
            # failed insert leaves the thread exactly as it was (#69).
            self.queue.put(item, transition=decision.transition)
        except (OSError, sqlite3.Error, ValueError) as exc:
            # Nothing was stored and nothing was committed, so the item stays unacked and the hub
            # offers it again; the attempt counter bounds a message that can never be stored.
            log.error("queue refused or failed on %s from %s: %s", message_id, sender, exc)
            return "unhandled", None
        return "queued", message_id

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
        path = self.state.directory / NOTICES
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
