"""A gate refusal reaches the sender — and a stranger still learns nothing (#50).

Two directions, asserted together on purpose: a fix that tells the refused sender its message died
must not turn the 403 path into an existence oracle. The negative here is the one that matters.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from knok.bridge import MAX_HANDLE_ATTEMPTS, MAX_REFUSAL_NOTICES_PER_HOUR, NOTICE_KEY
from knok.gate import Gate
from knok.hubclient import HubClient
from knok.policy import load as load_policy

from test_phase2 import DOMAIN, deployment, send


def apply_policy(bridge, path):
    """Rebuild one bridge's gate from the policy file on disk.

    #52 (PR #53) makes the bridge do this itself on the next poll; this branch is about what the
    gate does with a refusal, so it sets the precondition explicitly instead of depending on it.
    """
    policy = load_policy(path)
    bridge.policy = policy
    bridge.gate = Gate(policy, bridge.contacts, bridge.threads, bridge.rates)
    return policy


def policy_path(root, name):
    return root / "agents" / name / "policy.json"


def rewrite(root, name, **changes):
    """Edit one agent's policy file on disk. Returns nothing; ``apply_policy`` makes it live."""
    path = policy_path(root, name)
    document = json.loads(path.read_text())
    document.update(changes)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def notices_of(root, name):
    path = root / "agents" / name / "notices.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def record_sent_attempt(root, name, message_id, recipient_id):
    """Seed one ``sent.jsonl`` attempt: ``name`` sent ``message_id`` to ``recipient_id``.

    The ``send`` helper in ``test_phase2`` deposits straight through the hub client, the way
    the wire does — it does not do the CLI's bookkeeping (``_remember_attempt``), so a test
    that needs the sender to have a stored attempt writes it explicitly.
    """
    envelope = {
        "envelopeVersion": 1,
        "seq": 0,
        "message": {
            "kind": "message",
            "messageId": message_id,
            "contextId": "c-sent",
            "role": "agent",
            "parts": [{"kind": "text", "text": "hi"}],
        },
        "from": f"{name}@{DOMAIN}",
        "to": [recipient_id],
        "sentAt": "2026-11-21T00:00:00Z",
        "expiresAt": "2026-11-24T00:00:00Z",
    }
    record_attempt(root, name, envelope)


def record_attempt(root, name, envelope):
    """Append one attempt record, in the shape ``_remember_attempt`` writes."""
    path = root / "agents" / name / "sent.jsonl"
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(
            json.dumps({"recordedAt": "2026-11-21T00:00:00Z", "envelope": envelope}) + "\n"
        )


def notice_item(sender_id, notice, message_id="r-notice"):
    """One mailbox item carrying a refusal notice, the way the peer's bridge deposits it."""
    return {
        "from": sender_id,
        "message": {
            "kind": "message",
            "messageId": message_id,
            "contextId": "c-notice",
            "role": "agent",
            "parts": [{"kind": "text", "text": "refused"}],
            "metadata": {NOTICE_KEY: notice},
        },
    }


def test_a_refused_message_reaches_the_sender_as_a_notice(deployment):
    """The core claim: hub acked it, gate refused it, and the sender is told anyway.

    The sender is a pinned correspondent, refused under policy (not an accepted contact, not in
    the allow-list) — not a blocked one: blocked peers get silence, not a notice.
    """
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    context = "c-thread-50"

    rewrite(root, "muse", block=[], allow=[])
    apply_policy(muse, policy_path(root, "muse"))

    _, envelope = send(
        carl, muse.identity.agent_id, "are you there?", context=context, message_id="m-50"
    )
    # The CLI records every attempt in sent.jsonl before deposit; this helper deposits
    # directly, so the test does that bookkeeping — without a stored attempt addressed to
    # muse, the notice has no provenance and is dropped (#120).
    record_attempt(root, "carl", envelope)
    refused = muse.poll_once()
    assert refused["refused"] == 1, "the gate must refuse an unlisted sender"
    assert muse.queue.get() is None, "and nothing reaches the application"

    # The hub's copy is gone (the refusal was acked, so a page of refusals still advances)...
    assert muse.client.fetch()["messages"] == []
    # ...but the sender's bridge is handed the notice and records it.
    seen = carl.poll_once()
    assert seen["notices"] == 1, "the sender's bridge must receive and handle the notice"
    notices = notices_of(root, "carl")
    assert len(notices) == 1
    notice = notices[0]
    assert notice["kind"] == "refused"
    assert notice["from"] == muse.identity.agent_id
    assert notice["messageId"] == "m-50", "the notice names the message that died"
    assert notice["contextId"] == context, "and the thread, so a retry can reuse it (#48)"
    assert notice["rule"] == "policy"

    # The sender's own mailbox is clear: the notice was handled, not left to be re-offered.
    assert carl.client.fetch()["messages"] == []


def test_a_blocked_peer_gets_silence(deployment):
    """The paired negative that matters: blocking must look like nonexistence.

    A blocked peer's message is refused at the gate and recorded locally, but no notice is
    deposited back — a notice would confirm the identity is recognised and gated, and would
    distinguish blocked from never-seen (the same uniform-refusal reasoning as the #42 denial).
    """
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

    rewrite(root, "muse", block=[f"carl@{DOMAIN}"])
    apply_policy(muse, policy_path(root, "muse"))

    send(carl, muse.identity.agent_id, "are you there?", message_id="m-blocked")
    refused = muse.poll_once()
    assert refused["refused"] == 1, "the gate must refuse a blocked sender"
    assert muse.queue.get() is None, "and nothing reaches the application"

    # No notice is deposited back: the blocked peer sees nothing.
    assert carl.client.fetch()["messages"] == [], "a blocked peer must get silence"
    assert carl.poll_once()["notices"] == 0, "no notice is handled for a blocked peer"
    assert notices_of(root, "carl") == [], "no notice recorded for a blocked peer"

    # But the refusal is still recorded locally for the operator.
    record = json.loads(
        (root / "agents" / "muse" / "refused.jsonl").read_text().splitlines()[0]
    )
    assert record["messageId"] == "m-blocked"
    assert record["rule"] == "blocked"
    assert record["from"] == f"carl@{DOMAIN}"


def test_a_notice_is_not_a_message_in_a_thread(deployment):
    """It must not be queued, must not spend a reply expectation, and must not reach the inbox."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

    rewrite(root, "muse", block=[], allow=[])
    apply_policy(muse, policy_path(root, "muse"))
    _, envelope = send(carl, muse.identity.agent_id, "one", context="c-quiet", message_id="m-quiet")
    # As above: the notice muse sends back needs a stored attempt to correlate with (#120).
    record_attempt(root, "carl", envelope)
    muse.poll_once()
    assert carl.poll_once()["notices"] == 1

    assert carl.queue.get() is None, "a notice is transport, not mail"
    contexts = [
        row[0]
        for row in carl.threads._conn.execute("SELECT context FROM threads").fetchall()
    ]
    assert not any(context.startswith("c-notice-") for context in contexts), (
        "a notice must not create a thread with a reply expectation"
    )
    assert not (root / "agents" / "carl" / "inbox.jsonl").exists()


def test_the_refusal_is_recorded_locally_even_if_the_notice_fails(deployment):
    """If the peer's mailbox is unreachable, the operator still has the evidence."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

    rewrite(root, "muse", block=[], allow=[])
    apply_policy(muse, policy_path(root, "muse"))

    # A hub that refuses every deposit: the notice cannot be sent.
    class DeadHub(HubClient):
        def deposit(self, envelope):
            from knok.hubclient import HubError

            raise HubError("no route to the peer")

    muse.client = DeadHub(muse.state.hub_url, muse.identity)
    send(carl, muse.identity.agent_id, "into the void", message_id="m-void")
    assert muse.poll_once()["refused"] == 1

    record = json.loads(
        (root / "agents" / "muse" / "refused.jsonl").read_text().splitlines()[0]
    )
    assert record["messageId"] == "m-void"
    assert record["rule"] == "policy"
    assert record["from"] == f"carl@{DOMAIN}"


def test_an_unverifiable_sender_gets_no_notice(deployment):
    """The paired negative: a sender we cannot verify learns nothing, and the message is dropped."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

    # Muse has not learned carl's card (registry lag): the envelope cannot be verified at all.
    saved = muse.state.registry.pop(f"carl@{DOMAIN}")
    try:
        send(carl, muse.identity.agent_id, "who am i", message_id="m-unknown")
        for _ in range(MAX_HANDLE_ATTEMPTS):
            muse.poll_once()
    finally:
        muse.state.registry[f"carl@{DOMAIN}"] = saved

    assert not (root / "agents" / "muse" / "refused.jsonl").exists(), "not a gate refusal"
    dropped = (root / "agents" / "muse" / "dropped.jsonl").read_text().splitlines()
    assert "m-unknown" in dropped[0]
    # And nothing was sent back to the stranger: the uniform path stays uniform.
    assert carl.client.fetch()["messages"] == [], "an unverified sender must not be answered"


def test_the_public_reason_is_identical_for_every_rule(deployment):
    """``rule`` is internal; what a caller can observe is one string either way (§9)."""
    hub, bridges, root = deployment
    muse = bridges["muse"]
    from knok.contacts import REFUSED

    envelope = {
        "from": f"carl@{DOMAIN}",
        "message": {"kind": "message", "messageId": "m", "contextId": "c",
                    "role": "agent", "parts": [{"kind": "text", "text": "hi"}]},
    }
    rewrite(root, "muse", block=[f"carl@{DOMAIN}"])
    apply_policy(muse, policy_path(root, "muse"))
    blocked = muse.gate.decide(dict(envelope))

    rewrite(root, "muse", block=[], allow=[])
    apply_policy(muse, policy_path(root, "muse"))
    unlisted = muse.gate.decide(dict(envelope))

    assert blocked.allowed is False and unlisted.allowed is False
    assert blocked.reason == unlisted.reason == REFUSED, "the answer must not name the rule"
    assert (blocked.rule, unlisted.rule) == ("blocked", "policy")


def test_a_notice_must_name_a_message_sent_to_the_peer_who_refused_it(deployment):
    """#120: a pinned peer must not inject failure records for messages we never sent it.

    A notice is a statement about one of our messages, so the receiver correlates it with its
    own ``sent.jsonl`` before recording it: the named id must be an attempt this agent made,
    addressed to the peer the notice came from, and the rule must be one the gate defines.
    """
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    muse_id = muse.identity.agent_id

    # Carl really did send m-real to muse — and m-other-peer to someone else entirely.
    record_sent_attempt(root, "carl", "m-real", muse_id)
    record_sent_attempt(root, "carl", "m-other-peer", f"kiko@{DOMAIN}")

    def handle(message_id, rule="policy", frame_id="r-notice"):
        item = notice_item(
            muse_id, {"kind": "refused", "messageId": message_id, "rule": rule}, frame_id
        )
        return carl._handle_refusal_notice(
            item, muse_id, item["message"]["metadata"][NOTICE_KEY]
        )

    # A notice for a message carl never sent is dropped, and the frame is still acked.
    assert handle("m-never-sent") == ("refused", "r-notice")
    assert notices_of(root, "carl") == [], "an unprovenanced notice must not be recorded"

    # A notice for a message sent to a different peer is dropped too: the attempt exists,
    # but it was not addressed to the peer the notice came from.
    assert handle("m-other-peer") == ("refused", "r-notice")
    assert notices_of(root, "carl") == []

    # A notice with a rule the gate never defines is dropped, even for a real message.
    assert handle("m-real", rule="nonsense") == ("refused", "r-notice")
    assert notices_of(root, "carl") == []

    # A notice naming a message carl did send to muse, under a defined rule, is recorded.
    assert handle("m-real", rule="policy") == ("notices", "r-notice")
    recorded = notices_of(root, "carl")
    assert len(recorded) == 1
    assert recorded[0]["messageId"] == "m-real"
    assert recorded[0]["from"] == muse_id
    assert recorded[0]["rule"] == "policy"


def test_a_notice_flood_is_bounded(deployment):
    """A notice is handled before the gate, so it needs a bound of its own."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

    # The flood is about the cap, not provenance: the notice names a message carl really
    # sent to muse, so the provenance check passes and the cap is what bounds it (#120).
    record_sent_attempt(root, "carl", "m-x", muse.identity.agent_id)

    item = {
        "from": muse.identity.agent_id,
        "message": {
            "kind": "message",
            "messageId": "r-flood",
            "contextId": "c-notice-flood",
            "role": "agent",
            "parts": [{"kind": "text", "text": "refused"}],
            "metadata": {NOTICE_KEY: {"kind": "refused", "messageId": "m-x", "rule": "limits"}},
        },
    }
    for index in range(MAX_REFUSAL_NOTICES_PER_HOUR + 5):
        item["message"]["messageId"] = f"r-flood-{index}"
        carl._handle_refusal_notice(item, muse.identity.agent_id, item["message"]["metadata"][NOTICE_KEY])

    recorded = notices_of(root, "carl")
    assert len(recorded) == MAX_REFUSAL_NOTICES_PER_HOUR, "the cap must hold, not just log"


def test_a_malformed_notice_is_ignored_but_the_frame_is_acked(deployment):
    """Garbage from a pinned peer must not wedge the mailbox behind it."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    item = {
        "from": muse.identity.agent_id,
        "message": {
            "kind": "message",
            "messageId": "r-garbage",
            "contextId": "c-notice-garbage",
            "role": "agent",
            "parts": [{"kind": "text", "text": "??"}],
            "metadata": {NOTICE_KEY: {"kind": "refused"}},
        },
    }
    outcome, message_id = carl._handle_refusal_notice(
        item, muse.identity.agent_id, item["message"]["metadata"][NOTICE_KEY]
    )
    assert (outcome, message_id) == ("refused", "r-garbage"), "acked, not re-offered forever"
    assert notices_of(root, "carl") == []


def test_a_delivered_message_reaches_the_sender_as_a_frame(deployment):
    """#93, end to end: the sender's bridge records the hub's `delivered` frame.

    The point of the frame is that a sender polling its own mailbox learns something it could
    not learn before — that the message left the hub's store — without a reply from the agent.
    """
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    context = "c-delivered"

    _, envelope = send(carl, muse.identity.agent_id, "did you get this?", context=context)
    message_id = envelope["message"]["messageId"]
    record_attempt(root, "carl", envelope)

    # The recipient's bridge takes custody and acks; the hub then queues the frame to the sender.
    assert muse.poll_once()["queued"] == 1

    counts = carl.poll_once()
    assert counts["notices"] == 1
    delivered = [n for n in notices_of(root, "carl") if n.get("kind") == "delivered"]
    assert [n["messageId"] for n in delivered] == [message_id]
    assert delivered[0]["contextId"] == context
    # The frame is not mail: it never enters the thread and never reaches the application.
    assert carl.queue.get() is None
    # And the sender acked it away, so it does not come back.
    assert carl.client.fetch()["messages"] == []


def test_a_message_at_a_spent_seq_is_refused_and_the_sender_is_told(deployment):
    """#142: the follow-up that vanished. A second message at a used seq is refused by name.

    The queue used to answer ``duplicate`` — the silent answer reserved for a retry — so the
    bridge acked it, the hub deleted its copy and minted a ``delivered`` frame, and the sender
    believed a question had been asked that never reached the agent. Nothing about the wire
    changed: only the answer, and the notice that goes with it.
    """
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    context = "c-spent-seq-142"

    rewrite(root, "muse", block=[], allow=[carl.identity.agent_id])
    apply_policy(muse, policy_path(root, "muse"))

    _, first = send(carl, muse.identity.agent_id, "first", context=context,
                    message_id="m-142-first", seq=0)
    record_attempt(root, "carl", first)
    assert muse.poll_once()["queued"] == 1
    delivered = muse.queue.get()
    muse.queue.ack(delivered["message"]["messageId"])

    # The follow-up, at the seq the first one already spent.
    _, follow = send(carl, muse.identity.agent_id, "follow-up question", context=context,
                     message_id="m-142-second", seq=0)
    record_attempt(root, "carl", follow)

    counts = muse.poll_once()
    assert counts["conflict"] == 1, "a different message at a spent seq is a conflict"
    assert counts["duplicate"] == 0, "and not the silent answer a retry gets"
    assert counts["queued"] == 0, "nothing reached the application"
    assert muse.queue.get() is None

    # The sender is told, in the same vocabulary as a gate refusal.
    carl.poll_once()
    refused = [n for n in notices_of(root, "carl") if n["kind"] == "refused"]
    assert len(refused) == 1
    notice = refused[0]
    assert notice["messageId"] == "m-142-second"
    assert notice["rule"].startswith("sequence collision")

    # And the hub claimed no delivery: the ack named the id as undelivered, so no frame was
    # minted into the sender's mailbox (#93).
    assert carl.client.fetch()["messages"] == []


def test_a_notice_text_bounds_the_message_id_it_echoes(deployment):
    """The id in the body is peer-controlled; it is bounded where the notice is composed (#142).

    The receiver already refuses a notice whose fields are overlong, so this is defence in depth
    rather than a live hole — but a string a peer chose should not be assembled into a message
    without a limit at the point it is assembled.
    """
    hub, bridges, root = deployment
    muse = bridges["muse"]
    long_id = "m-" + "a" * 4000

    assert muse._send_refusal_notice(
        "carl@hub.local", long_id, "c-long-id", "sequence collision", datetime.now(timezone.utc)
    )

    body = bridges["carl"].client.fetch()["messages"]
    texts = [
        part.get("text", "")
        for envelope in body
        for part in (envelope.get("message") or {}).get("parts", [])
    ]
    assert texts, "the notice was deposited"
    assert all(len(text) < 400 for text in texts), "the echoed id is bounded"


def test_a_conflict_with_no_sender_is_recorded_rather_than_dropped(deployment):
    """The one silent case, named: no sender means nobody to notify — but the operator still sees it.

    A verified envelope always names a sender, so this path is unreachable from the wire; the test
    exists so the decision is explicit in the record instead of being the shape of an early return.
    """
    hub, bridges, root = deployment
    muse = bridges["muse"]

    muse._refuse_conflict({"message": {"contextId": "c-no-sender"}}, "m-orphan")

    rows = [
        json.loads(line)
        for line in (root / "agents" / "muse" / "refused.jsonl").read_text().splitlines()
    ]
    recorded = [row for row in rows if row["messageId"] == "m-orphan"]
    assert len(recorded) == 1
    assert recorded[0]["from"] is None
    assert recorded[0]["rule"] == "sequence collision"
    assert notices_of(root, "muse") == [], "no notice sent: there is nobody to address"
