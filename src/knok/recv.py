"""`knok recv`: pull one batch straight from the hub and print it.

The bridge exists for agents that run a process. Some agents cannot: a sandboxed agent has no
socket, and an agent that only exists for the duration of a job has nowhere to keep a poll loop.
For those, a one-shot fetch is the only shape available — and it is a different contract from the
bridge, so it says so loudly rather than pretending to be one.

What it does: sign a `GET /v1/mail`, print each envelope as one JSON line on stdout, then ack the
batch. Acking after printing means the caller's stdout is the durable sink; if that stdout is not
durable, the message is lost on the next failure. The bridge solves this with a local queue and an
fsync before ack; this command has nowhere to put a queue, so it does not offer at-least-once.

A hub transport frame (`expired`) is in the same mailbox as mail and must be acked the same way,
by the `messageId` it carries at the top level rather than inside `message`; an unacked frame is
re-printed by every later `recv` until the frame TTL sweeps it.

A message the gate would refuse is not printed: revocation and blocking are enforced at the
receiver as well as at deposit (§9, scenario 11, #51). The gate is the same object the bridge
builds — policy, contacts, threads, rates — read fresh on every call, so a peer revoked since the
mail was queued is refused here too. A refused envelope is still acked: it counts as handled, like
the bridge's refusal, so the mailbox advances past it instead of re-offering it on every recv.
The refusal is logged to stderr; stdout stays the durable sink for envelopes only. Hub transport
frames are not mail and are not gated: they print and ack exactly as before.

It also bypasses the queue's `seq` ordering and dedupe: a `recv` and a bridge on the same identity
would fight, and a repeated `recv` after a lost stdout can see a message twice before the ack lands.
Use it when there is no daemon and the output goes somewhere that keeps it.

    KNOK_AGENT=sunny@knok.local KNOK_STATE=~/.knok KNOK_HUB_URL=http://hub:8080 \\
        python -m knok.cli recv --limit 20
"""

from __future__ import annotations

import json
import sys

from . import policy as policy_mod
from .bridge import NOTICE_KEY, BridgeState
from .contacts import Contacts
from .gate import Gate, Threads
from .hubclient import HubClient
from .identity import Identity
from .policy import Policy
from .rates import Rates


def _gate_for(state: BridgeState) -> tuple[Gate, list]:
    """The inbound gate for this agent's state, and the stores that own it.

    The policy is the file when the agent has one; without it, the pinned registry is the
    allow-list. That is a private deployment's pre-approval (``provision.py`` writes the same
    allow-list into a policy): the operator pins a card to say these agents may talk, so a card
    removed from the registry revokes the peer for ``recv`` as surely as a policy edit does.
    Without a policy file this is a recv-only fallback, not parity with the bridge: the pinned
    registry becomes the allow-list, there is no block list and no limits, so a pinned peer is
    admitted and can only be revoked by removing its card. With a policy file the gate is the
    object the bridge builds, so a sender the bridge would refuse is refused here too — including
    one revoked since the mail was queued, because policy and registry are read fresh on every
    call.

    A policy file that cannot be read, or names another agent, is a misconfiguration, not a
    reason to fall back: the call fails loudly rather than silently opening the gate.
    """
    if state.policy_path.exists():
        try:
            policy = policy_mod.load(state.policy_path)
        except policy_mod.PolicyError as exc:
            raise SystemExit(f"cannot load policy {state.policy_path}: {exc}")
        if policy.agent_id != state.agent_id:
            raise SystemExit(
                f"policy {state.policy_path} is for {policy.agent_id}, not {state.agent_id}"
            )
    else:
        policy = Policy(
            agent_id=state.agent_id,
            contact_policy="closed",
            deployment="private",
            allow=frozenset(peer for peer in state.registry if peer != state.agent_id),
            block=frozenset(),
            limits={},
            probation=False,
        )
    rates = Rates(state.directory / "rates.db")
    contacts = Contacts(state.directory / "contacts.db", rates=rates)
    # The same file the queue uses: since #69 a decision and the message it decides on commit
    # together, and a Threads opened on threads.db reads an empty table - every reply recv judges
    # looks unsolicited and is refused, while the bridge counts it correctly in the other file.
    threads = Threads(state.directory / "queue.db")
    gate = Gate(policy, contacts, threads, rates)
    return gate, [rates, contacts, threads]


def _is_refusal_notice(envelope: dict) -> bool:
    """True when this envelope is a notice about one of our own messages.

    Same key the bridge uses (``bridge.NOTICE_KEY``), for the same reason: a notice is not
    addressed mail, it is a report that something we sent was refused or expired, and it must not
    be judged as inbound traffic.
    """
    message = envelope.get("message")
    if not isinstance(message, dict):
        return False
    metadata = message.get("metadata")
    return isinstance(metadata, dict) and NOTICE_KEY in metadata


def _ack_id(envelope: object) -> str | None:
    """The id an ack must carry for this row, or ``None`` when it carries none.

    A peer envelope nests it as ``message.messageId``. A hub transport frame (``expired``) is not a
    Message and has no ``message`` key: the id of the envelope it reports sits at the top level, and
    the hub files that frame in the mailbox under exactly that id — so it is what an ack deletes.
    """
    if not isinstance(envelope, dict):
        return None
    message = envelope.get("message")
    if isinstance(message, dict) and isinstance(message.get("messageId"), str):
        return message["messageId"]
    top_level = envelope.get("messageId")
    return top_level if isinstance(top_level, str) else None


def recv_once(state: BridgeState, identity: Identity, limit: int = 20) -> int:
    """Fetch, print and ack one batch. Returns the number of envelopes handed out.

    Both the state and the already-loaded identity are supplied by the caller: an identity is only
    trustworthy once it is bound to the registry's fingerprint (§4, no trust-on-first-use), and that
    binding belongs where the registry is read, not in here.

    A message the gate would refuse is not printed (§9, #51): the gate is built from this agent's
    state and read fresh on every call, so a peer revoked since the mail was queued is refused
    here too. A refused envelope is still acked, so the mailbox advances; the refusal is logged
    to stderr, never to stdout, which stays the durable sink for envelopes only. Hub transport
    frames (``expired``, ``dead``) are not mail and are not gated: they print and ack exactly as
    before.
    """
    gate, closers = _gate_for(state)
    try:
        client = HubClient(state.hub_url, identity)
        body = client.fetch(limit=limit)
        envelopes = body.get("messages") or body.get("envelopes") or []
        printed = 0
        message_ids: list[str] = []
        for envelope in envelopes:
            if not isinstance(envelope, dict):
                continue
            if envelope.get("kind") in {"expired", "dead"}:
                # A hub transport frame is not mail: it carries no sender to gate, and the
                # bridge handles it before the gate for the same reason.
                sys.stdout.write(json.dumps(envelope, sort_keys=True) + "\n")
                printed += 1
            elif "message" not in envelope:
                # Form 2 (sealed). There is no message for the gate to judge, and where it is
                # decrypted is still open (#70). Left at the hub rather than acked away: an ack
                # would destroy mail recv cannot read, and a refusal here would look like a
                # policy decision rather than a limitation.
                sys.stderr.write(
                    "sealed envelope left at the hub: no form 1 message to gate or print\n"
                )
                continue
            elif _is_refusal_notice(envelope):
                # A notice is a statement about a message we sent, not mail for us: the bridge
                # handles it before the gate so it can never enter a thread or a decision, and
                # recv must do the same or a recv-only agent never learns its message died.
                sys.stdout.write(json.dumps(envelope, sort_keys=True) + "\n")
                printed += 1
            else:
                decision = gate.decide(envelope)
                if decision.allowed:
                    sys.stdout.write(json.dumps(envelope, sort_keys=True) + "\n")
                    printed += 1
                else:
                    # Refused, not printed — and still acked, so the mailbox advances past it
                    # instead of re-offering it on every recv. The refusal is the operator's
                    # record; stdout is only for envelopes.
                    message = envelope.get("message") if isinstance(envelope, dict) else None
                    message_id = (
                        message.get("messageId") if isinstance(message, dict) else None
                    )
                    sender = envelope.get("from") if isinstance(envelope, dict) else None
                    # The refusal string is uniform on purpose: `rule` is an internal category
                    # that gate.py says never leaves the process, and `blocked` is never quoted
                    # anywhere. stderr is this operator's, but the contract is the contract.
                    sys.stderr.write(
                        f"gate refused {message_id or '?'} from {sender or '?'}"
                        f" ({decision.reason or 'refused'})\n"
                    )
            ack_id = _ack_id(envelope)
            if ack_id is not None:
                message_ids.append(ack_id)
        sys.stdout.flush()
        if message_ids:
            client.ack(message_ids)
        return printed
    finally:
        for closable in closers:
            try:
                closable.close()
            except Exception:  # a close must never mask the reason we are closing
                pass
