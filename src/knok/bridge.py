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
from .gate import Gate, REFUSAL_RULES, Threads
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

#: How long the bridge keeps a row in its local audit files (#124). Thirty days aligns with the
#: spec's own clocks: hub-log metadata is retained 30 days (SPEC §10) and dead letters 30 days
#: (SPEC §6). The hub's 72-hour mailbox TTL does not prune these bridge-local copies, so the
#: bridge prunes them itself, on its poll loop.
LEDGER_RETENTION = timedelta(days=30)
#: How often the poll loop prunes: retention is 30 days, so once a day of process time is plenty,
#: and re-reading four files every two-second poll would be pure churn.
PRUNE_LEDGER_INTERVAL_SECONDS = 24 * 3600
#: The bridge-owned audit files, and the timestamp keys that date a row in each. A notice row is
#: dated by whichever of its event times it carries — ``receivedAt`` for a peer refusal,
#: ``expiredAt``/``deadedAt`` for a hub frame, ``detectedAt``/``releasedAt`` for a gap or late
#: notice. ``sent.jsonl`` and ``retries.jsonl`` are not here: the CLI and the retry adapter own
#: them, and their retention is their own decision.
LEDGER_FILES: dict[str, tuple[str, ...]] = {
    "delivery.jsonl": ("at",),
    "refused.jsonl": ("at",),
    "dropped.jsonl": ("at",),
    NOTICES: ("receivedAt", "expiredAt", "deadedAt", "deliveredAt", "detectedAt", "releasedAt", "at"),
}
#: Every file a bridge appends JSON lines to. A crash mid-append can leave a torn final line in
#: any of them; all five are repaired the same way (#114).
JSONL_STATE_FILES = ("delivery.jsonl", NOTICES, "refused.jsonl", "dropped.jsonl", "inbox.jsonl")


def _find_line_start(handle, end: int) -> int:
    """Index just after the last ``\\n`` before ``end`` (0 when there is none).

    ``handle`` is open in binary mode; ``end`` is the byte offset the line ends at. Scans
    backwards in blocks, so a long file costs one line's worth of reads, not the whole file.
    """
    block = 65536
    pos = end
    while pos > 0:
        start = max(0, pos - block)
        handle.seek(start)
        chunk = handle.read(pos - start)
        idx = chunk.rfind(b"\n")
        if idx != -1:
            return start + idx + 1
        pos = start
    return 0


def _truncate_torn_tail(path: Path) -> None:
    """Drop a torn trailing line from a JSONL file, if it has one (#114).

    An append is one ``write`` of one line plus fsync, so a crash during it can leave a partial
    final line: bytes on disk, no complete record. The next append would glue its record onto
    the fragment and corrupt both lines. Only the final line can be torn this way — every line
    before it was complete when a later line was written after it — so the repair is
    conservative: drop the tail when it is not a complete, valid JSON line, and leave every
    complete line before it alone. A newline-terminated last line that is not valid JSON is a
    fused line from a crash before this repair existed, and is dropped the same way.

    Best effort, never fatal: a file that cannot be read or truncated is logged and left for
    the append's own error handling, and the repair runs again on the next attempt.
    """
    try:
        with open(path, "r+b") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if size == 0:
                return
            tail_start = _find_line_start(handle, size)
            if tail_start < size:
                # No trailing newline: the final line never completed.
                handle.truncate(tail_start)
                handle.flush()
                os.fsync(handle.fileno())
                log.warning("truncated a torn final line in %s (%d bytes dropped)",
                            path, size - tail_start)
                return
            # Ends with a newline, but the last line may still be a fused fragment.
            last_start = _find_line_start(handle, size - 1)
            handle.seek(last_start)
            try:
                json.loads(handle.read(size - last_start))
            except ValueError:
                handle.truncate(last_start)
                handle.flush()
                os.fsync(handle.fileno())
                log.warning("truncated an unparseable final line in %s (%d bytes dropped)",
                            path, size - last_start)
    except OSError as exc:
        # No file yet is the ordinary case; anything else is logged, not raised — the append
        # that follows will report a write it cannot make in its own terms.
        if not isinstance(exc, FileNotFoundError):
            log.warning("could not repair %s; leaving it for the next append: %s", path, exc)


def iso(moment: datetime) -> str:
    """The one timestamp format the wire and the logs both use."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


#: The longest a peer-supplied protocol identifier may be (#123). Identifiers minted here are a
#: few dozen characters; anything far longer is not an id, it is a payload aimed at a log.
MAX_PROTOCOL_ID_LENGTH = 256
#: A gate rule is one short category word (``policy``, ``limits``, ``thread``, ``malformed``).
MAX_RULE_LENGTH = 64


def _is_protocol_id(value: Any, *, limit: int = MAX_PROTOCOL_ID_LENGTH) -> bool:
    """True when ``value`` is a string safe to carry into a log line or a terminal row.

    A peer-controlled identifier that is not printable — a newline, a tab, a bell — makes one
    event print as several, including text that resembles a second event. Length is bounded for
    the same reason: a log line must stay a line. Unicode that prints is accepted; only control
    characters and overlong values are refused.
    """
    return (
        isinstance(value, str)
        and 0 < len(value) <= limit
        and all(ch.isprintable() for ch in value)
    )


def safe_log_text(value: Any, *, limit: int = MAX_PROTOCOL_ID_LENGTH) -> str:
    """Render an untrusted value as one safe token for a log line or terminal row (#123).

    Every character that is not printable is replaced by its ``\\uXXXX`` escape, so the value stays
    readable and stays on one line; the result is truncated past ``limit`` characters. This is the
    second half of the notice-boundary validation: a value that arrives through a path the
    validator never sees (a hub frame, a re-offered id) is still escaped where a human reads it.
    ``None`` renders ``-``; anything else is stringified first.
    """
    if value is None:
        return "-"
    text = value if isinstance(value, str) else str(value)
    rendered = "".join(ch if ch.isprintable() else f"\\u{ord(ch):04x}" for ch in text)
    if len(rendered) > limit:
        rendered = rendered[:limit] + "…"
    return rendered


def _ledger_row_time(row: dict[str, Any], keys: tuple[str, ...]) -> datetime | None:
    """The instant a ledger row dates itself by, or ``None`` when it carries no readable time.

    Rows are dated by the timestamp the writer put on them, in the one format the bridge uses
    (``%Y-%m-%dT%H:%M:%SZ``). A row with no readable timestamp is not datable, and the pruner
    treats that as "keep": deleting evidence it cannot read would be the silent loss this file
    exists to prevent.
    """
    for key in keys:
        value = row.get(key)
        if isinstance(value, str):
            try:
                return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def prune_ledgers(directory: Path, *, retention: timedelta = LEDGER_RETENTION,
                  now: datetime | None = None) -> dict[str, int]:
    """Drop audit rows older than ``retention`` from the bridge's ledger files (#124).

    Every file in ``LEDGER_FILES`` is read, rows past retention are removed, and the file is
    replaced atomically (temp file, fsync, ``os.replace``, directory fsync), so a crash mid-prune
    leaves the old file or the new one, never a half-written one. A file that does not exist is
    not created; a row with no readable timestamp, and a line that is not JSON at all, are kept.
    A file that cannot be read or replaced is left exactly as found and logged, never deleted.

    Returns ``{filename: rows removed}`` for the files that lost rows. Pruning these files does
    not securely erase copies elsewhere — SQLite WAL pages and nightly backups keep their own
    schedule — it bounds what the live audit trail holds.
    """
    moment = now or datetime.now(timezone.utc)
    removed: dict[str, int] = {}
    for name, keys in LEDGER_FILES.items():
        path = directory / name
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            log.error("could not read %s to prune it; leaving it alone: %s", name, exc)
            continue
        kept: list[str] = []
        dropped = 0
        for line in lines:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                kept.append(line)
                continue
            stamp = _ledger_row_time(row, keys) if isinstance(row, dict) else None
            if stamp is not None and moment - stamp > retention:
                dropped += 1
                continue
            kept.append(line)
        if not dropped:
            continue
        tmp = directory / f".{name}.prune-{os.getpid()}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                for line in kept:
                    handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            try:
                dir_fd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        except OSError as exc:
            log.error("could not prune %s; leaving it alone: %s", name, exc)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            continue
        removed[name] = dropped
        log.info("pruned %d row(s) older than %d days from %s", dropped, retention.days, name)
    return removed


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


def item_digest(item: Any) -> str:
    """SHA-256 of the canonical JSON of an item, for correlating a record with a copy elsewhere.

    The digest is the whole item reduced to one hex string: enough for an operator holding the
    hub-side copy to confirm it is the same item, and nothing an operator without that copy can
    reconstruct a body from.
    """
    import hashlib

    return "sha256:" + hashlib.sha256(
        json.dumps(item, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


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
        #: Monotonic time of the last ledger prune, or ``None`` before the first poll. Pruning
        #: runs at most once a day of process time (#124); the field is what makes that true.
        self._last_prune: float | None = None

        state.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(state.directory, 0o700)
        # A crash during an earlier append can leave a torn final line in a state file; heal all
        # five before this process writes anything, so a reader never meets a fragment the next
        # append would have glued a record onto (#114). The append path repairs again before
        # every write, for a fragment left by a partial write in this same lifetime.
        for name in JSONL_STATE_FILES:
            _truncate_torn_tail(state.directory / name)

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

    def _prune_ledgers_if_due(self) -> dict[str, int]:
        """Prune audit rows past retention, at most once a day of process time (#124).

        Called at the top of every poll, before any fetch: the rows pruned are at least 30 days
        old, so nothing on the page being fetched can be among them, and the prune never runs
        between a delivery row being written and its ack.
        """
        now = self._clock()
        if self._last_prune is not None and now - self._last_prune < PRUNE_LEDGER_INTERVAL_SECONDS:
            return {}
        self._last_prune = now
        try:
            return prune_ledgers(self.state.directory)
        except Exception:
            # Pruning is housekeeping: a failure here must never stop the poll.
            log.exception("ledger pruning failed; continuing")
            return {}

    def poll_once(self) -> dict[str, int]:
        """Fetch one page, handle it in order, record it, ack what was handled.

        Returns counts. A message counts as handled when it was either queued durably or refused at
        the gate; a message that could not be handled at all (unverifiable sender, unknown card) is
        left unacked so the hub offers it again, because the alternative is silently dropping mail.

        Every fetched item leaves one row in ``delivery.jsonl`` saying what was decided about it,
        and the rows reach the disk *before* the hub ack that deletes its copy. That ordering is the
        point: ``duplicate`` and ``dropped`` are decisions that destroy mail, and once the hub has
        been told to drop it the row is the only evidence the message ever arrived.
        """
        self._prune_ledgers_if_due()
        self.reload_policy_if_changed()
        self.reload_registry_if_changed()
        try:
            page = self.client.fetch(limit=self.batch)
        except HubError as exc:
            log.warning("fetch failed: %s", exc)
            return {"fetched": 0, "queued": 0, "duplicate": 0, "late": 0, "refused": 0,
                    "notices": 0, "unhandled": 1, "dropped": 0}

        counts = {"fetched": 0, "queued": 0, "duplicate": 0, "late": 0, "refused": 0,
                  "notices": 0, "unhandled": 0, "dropped": 0}
        handled: list[str] = []
        undelivered: list[str] = []
        ledger: list[dict[str, Any]] = []
        for item in page.get("messages", []):
            counts["fetched"] += 1
            outcome, message_id = self._handle(item)
            if message_id is None:
                key = item_key(item)
                attempts = self._attempts.get(key, 0) + 1
                self._attempts[key] = attempts
                if attempts < MAX_HANDLE_ATTEMPTS:
                    counts["unhandled"] += 1
                    ledger.append(self._delivery_record(item, "unhandled", key))
                    continue
                # Bounded and now exhausted: acknowledge it away so the mailbox can advance, and
                # leave a record. Re-offering it a sixth time only starves everything behind it.
                log.error("dropping an unhandleable item after %d attempts: %s", attempts,
                          safe_log_text(key))
                if not self._record_drop(item, key):
                    # The record is the only evidence this message ever existed. Without it the ack
                    # would erase the message and leave nothing behind, so the drop waits instead.
                    counts["unhandled"] += 1
                    ledger.append(self._delivery_record(item, "unhandled", key))
                    continue
                del self._attempts[key]
                counts["dropped"] += 1
                handled.append(key)
                if isinstance(key, str):
                    # Giving up is custody taken without delivery: ack it so the hub stops
                    # offering it, but never tell the sender it arrived (#93).
                    undelivered.append(key)
                ledger.append(self._delivery_record(item, "dropped", key))
                continue
            counts[outcome] += 1
            handled.append(message_id)
            if outcome in {"refused", "dropped"} and isinstance(message_id, str):
                # Custody was taken but the application never saw it. The hub still has to stop
                # offering it, so it is acked — but it must not produce a delivered frame to the
                # sender, which already gets the refusal or the drop record (#93).
                undelivered.append(message_id)
            ledger.append(self._delivery_record(item, outcome))

        # Record, then hand the hub permission to forget. If the ledger cannot be written, nothing
        # on this page is acked: the hub keeps offering these, and a message the queue already
        # holds comes back as a duplicate it can recognise. Losing one to a full disk would repeat
        # the failure this file exists to catch.
        if not self._record_deliveries(ledger):
            # The counts describe what the hub was told, and it was told nothing: every item on
            # this page is still its problem, whatever this bridge did with it locally.
            counts = {"fetched": counts["fetched"], "queued": 0, "duplicate": 0, "late": 0,
                      "refused": 0, "notices": 0, "unhandled": len(ledger), "dropped": 0}
            handled = []
            undelivered = []

        if handled:
            try:
                self.client.ack(handled, undelivered)
            except HubError as exc:
                # Not fatal: the hub will offer these again and the queue dedupes them.
                log.warning("ack failed (%d ids): %s", len(handled), exc)

        if self.deliver:
            counts["delivered"] = self.drain()
        return counts

    def _delivery_record(self, item: Any, outcome: str, key: str | None = None) -> dict[str, Any]:
        """The row one fetched item leaves in ``delivery.jsonl``.

        ``outcome`` is what ``_handle`` decided plus the two the caller can add (``dropped`` when
        the attempt allowance is spent, ``unhandled`` when the item is left at the hub). The row
        carries enough of the envelope to answer "which message, from whom, in which thread, at
        which seq" without opening the queue — a message that never reaches the inbox has no other
        place to be found.
        """
        record: dict[str, Any] = {
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "messageId": key or item_key(item),
            "outcome": outcome,
        }
        if isinstance(item, dict):
            message = item.get("message")
            for field in ("kind", "from", "to", "seq"):
                if field in item:
                    record[field] = item[field]
            if isinstance(message, dict) and isinstance(message.get("contextId"), str):
                record["contextId"] = message["contextId"]
        return record

    def _append_jsonl(self, path: Path, records: list[dict[str, Any]]) -> None:
        """Append records as fsynced JSON lines. Raises OSError when they cannot be written.

        A torn final line from a crash during an earlier append is truncated first, so the new
        records never glue onto a fragment and corrupt the file (#114). The records go out in
        one ``write``: a crash during it can tear at most the page's last record, and the next
        repair drops exactly that.
        """
        _truncate_torn_tail(path)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("".join(
                json.dumps(record, sort_keys=True, default=str) + "\n" for record in records
            ))
            handle.flush()
            os.fsync(handle.fileno())

    def _record_deliveries(self, records: list[dict[str, Any]]) -> bool:
        """Append the page's delivery rows, fsynced, before any of them is acked.

        False when the ledger cannot be written; the caller then acks nothing. One fsync per page,
        because the guarantee is about what is on disk before the ack, not about how many writes it
        took to get there.
        """
        if not records:
            return True
        path = self.state.directory / "delivery.jsonl"
        try:
            self._append_jsonl(path, records)
            return True
        except OSError as exc:
            log.error("could not write the delivery ledger; acking nothing this pass: %s", exc)
            return False

    def _handle(self, item: Any) -> tuple[str, str | None]:
        """Handle one mailbox item. Returns (outcome, messageId-or-None)."""
        if not isinstance(item, dict):
            return "unhandled", None

        if item.get("kind") in {"expired", "dead", "delivered"}:
            return self._handle_frame(item)

        sender = item.get("from")
        if not isinstance(sender, str):
            return "unhandled", None
        # The card is asked about as of the envelope's own ``sentAt``, matching transport and the
        # hub (decision 0002): a card that lapsed this morning must still account for a message
        # signed yesterday, and must not account for one signed after it lapsed.
        public_key = self.public_key_of(sender, at=sent_at(item))
        if public_key is None:
            log.warning("no trusted card for sender %s; leaving the message at the hub",
                        safe_log_text(sender))
            return "unhandled", None
        ok, reason = verify_envelope(item, public_key)
        if not ok:
            log.warning("refused an unverifiable envelope from %s: %s", safe_log_text(sender),
                        safe_log_text(reason))
            return "unhandled", None

        message = item.get("message")
        if not isinstance(message, dict):
            # Sealed (form 2): its contextId is inside the sealed body, so neither the gate nor the
            # queue can order it before decryption. Decision 0003 puts the decryption here, at
            # admission — this branch is where that step goes, and until it exists a sealed item is
            # left at the hub rather than guessed at (#70, #83).
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
            # Named for what it is: no work was done and nothing new is stored, so reporting this
            # as "queued" would put a delivery in the counts that never happened. A re-offer after
            # a lost hub ack is ordinary; a re-offer of an id whose message the queue does *not*
            # hold is the shape #79 could not see, and it says ``duplicate`` here too.
            log.info("re-offered message %s is already queued; acking without gate work",
                     safe_log_text(message_id))
            return "duplicate", message_id

        decision = self.gate.decide(item)
        if not decision.allowed:
            # Recorded as handled: the hub must stop offering it, or a 50-message page that is all
            # refusals never advances (HUB.md, "ack means handled").
            log.info("gate refused %s from %s: %s", safe_log_text(message_id),
                     safe_log_text(sender), safe_log_text(decision.reason))
            self._refuse(item, decision, message_id)
            return "refused", message_id

        try:
            # The gate's answer is applied here, by the queue, in the insert's transaction: a
            # failed insert leaves the thread exactly as it was (#69).
            result = self.queue.put(item, transition=decision.transition)
        except (OSError, sqlite3.Error, ValueError) as exc:
            # Nothing was stored and nothing was committed, so the item stays unacked and the hub
            # offers it again; the attempt counter bounds a message that can never be stored.
            log.error("queue refused or failed on %s from %s: %s", safe_log_text(message_id),
                      safe_log_text(sender), safe_log_text(exc))
            return "unhandled", None
        # ``put`` answers three ways and the difference is mail: ``accepted`` stored it, ``late``
        # stored it out of order, ``duplicate`` stored *nothing* and the envelope is dropped. The
        # hub is acked on all three, so flattening this to "queued" is how messages were fetched,
        # acknowledged and never seen while the poll log said they had arrived (#79).
        return ("queued" if result == "accepted" else result), message_id

    def _handle_frame(self, frame: dict[str, Any]) -> tuple[str, str | None]:
        hub_card = self.state.registry.get(frame.get("from", ""))
        if hub_card is None:
            return "unhandled", None
        from .identity import public_key_from_b64

        if not verify_frame(frame, public_key_from_b64(hub_card["bridge"]["publicKey"])):
            log.warning("dropped a transport frame that is not hub-signed: %r", frame.get("kind"))
            return "unhandled", None
        message_id = frame.get("messageId")
        kind = frame.get("kind")
        when = frame.get("expiredAt") or frame.get("deliveredAt")
        log.info(
            "notice: %s %s at %s (context %s)",
            safe_log_text(message_id),
            safe_log_text(kind),
            safe_log_text(when),
            safe_log_text(frame.get("contextId")),
        )
        if not self._record_notice(frame):
            # The frame is the only evidence the message expired or died — the body is already
            # gone — so without it on disk the frame stays at the hub and the bounded attempt
            # counter decides, rather than being acked away. The same write-success condition
            # the local queue-notice path in drain and the refusal-notice path already apply.
            return "unhandled", None
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
            log.error("could not tell %s that %s was refused: %s", safe_log_text(sender),
                      safe_log_text(message_id), safe_log_text(exc))
            return False

    def _sent_to(self, message_id: str, recipient: str) -> bool:
        """Whether this agent recorded sending ``message_id`` to ``recipient`` (#120).

        Correlates a refusal notice with ``sent.jsonl`` via ``read_attempts``: the stored
        envelope for the named id must exist, and its ``to`` must name this peer. The import
        is local because ``retry`` imports ``NOTICES`` from this module, so a top-level
        import would be circular.
        """
        from .retry import read_attempts

        attempt = read_attempts(self.state.directory).get(message_id)
        return isinstance(attempt, dict) and recipient in (attempt.get("to") or [])

    def _handle_refusal_notice(self, item: dict[str, Any], sender: str, notice: Any):
        """Record a peer's refusal of one of our messages, then let the hub drop it.

        This is the receiving half of #50: the sender learns, in its own ``notices.jsonl``, that
        its message was refused and under which rule — instead of waiting forever for a reply that
        cannot come.

        A notice is a statement about one of our messages, so it is recorded only when it proves
        it: the named ``messageId`` must be an attempt this agent recorded in ``sent.jsonl``
        addressed to this peer, and the rule must be one the gate defines (SPEC §9: nothing in
        a notice may describe anyone but the sender's own message). Anything else is dropped —
        a pinned peer must not be able to inject false failure records for messages we never
        sent it (#120). A dropped notice is still acked, so it cannot wedge the mailbox.
        """
        message_id = item["message"]["messageId"]
        moment = datetime.now(timezone.utc)
        if not isinstance(notice, dict) or not isinstance(notice.get("messageId"), str):
            log.warning("ignoring a malformed refusal notice from %s", safe_log_text(sender))
            return "refused", message_id
        if (
            not _is_protocol_id(notice.get("messageId"))
            or (notice.get("contextId") is not None
                and not _is_protocol_id(notice.get("contextId")))
            or (notice.get("rule") is not None
                and not _is_protocol_id(notice.get("rule"), limit=MAX_RULE_LENGTH))
        ):
            # A notice is a peer-controlled string that lands in our logs and terminal. A field
            # that is not printable or not bounded is not a refusal to record, it is a forgery
            # aimed at the reader (#123) — acked like any malformed notice, never stored.
            log.warning(
                "ignoring a refusal notice from %s with an unprintable or overlong field",
                safe_log_text(sender),
            )
            return "refused", message_id
        if notice.get("rule") not in REFUSAL_RULES:
            # A notice naming a rule the gate never defines is not a gate answer (#120).
            log.warning(
                "ignoring a refusal notice from %s with unknown rule %r",
                safe_log_text(sender),
                notice.get("rule"),
            )
            return "refused", message_id
        if not self._sent_to(notice["messageId"], sender):
            # SPEC §9: a notice may describe only the sender's own message. Without a stored
            # attempt addressed to this peer, the notice is an unverified claim about a message
            # we may never have sent — recording it would let a pinned peer inject false
            # failures into notices.jsonl and mislead the retry CLI (#120).
            log.warning(
                "ignoring a refusal notice from %s for %s: no sent attempt to that peer",
                safe_log_text(sender),
                safe_log_text(notice["messageId"]),
            )
            return "refused", message_id
        if (
            self.rates.count("notice", sender, moment, timedelta(hours=1))
            >= MAX_REFUSAL_NOTICES_PER_HOUR
        ):
            # A pinned peer can still flood us: a notice is handled before the gate, so §9's
            # message counters never see it. Bound our own log rather than the sender's mailbox.
            log.error("too many refusal notices from %s; not recording %s",
                      safe_log_text(sender), safe_log_text(message_id))
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
            safe_log_text(sender),
            safe_log_text(notice["messageId"]),
            safe_log_text(notice.get("rule")),
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
            self._append_jsonl(path, [record])
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

        The record is metadata only (#122): a dropped item is one the bridge could not verify or
        handle, so keeping the complete item would retain the body of a message the bridge never
        accepted — including one from a sender with no trusted card. What is kept is the key, the
        time, the sender/kind/messageId when the item safely carries them, and a digest of the
        item, which is what correlates this record with a hub-side copy. The ``delivery.jsonl``
        ``dropped`` row names the decision; this file names the item, without its content.
        """
        path = self.state.directory / "dropped.jsonl"
        record: dict[str, Any] = {
            "key": key,
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "itemDigest": item_digest(item),
        }
        if isinstance(item, dict):
            for field in ("kind", "from"):
                if isinstance(item.get(field), str):
                    record[field] = item[field]
            message = item.get("message")
            if isinstance(message, dict):
                if "kind" not in record and isinstance(message.get("kind"), str):
                    record["kind"] = message["kind"]
                if isinstance(message.get("messageId"), str):
                    record["messageId"] = message["messageId"]
        try:
            self._append_jsonl(path, [record])
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
            self._append_jsonl(path, [frame])
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
        self._append_jsonl(path, [envelope])

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
