"""A gate refusal reaches the sender — and a stranger still learns nothing (#50).

Two directions, asserted together on purpose: a fix that tells the refused sender its message died
must not turn the 403 path into an existence oracle. The negative here is the one that matters.
"""

from __future__ import annotations

import json

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


def test_a_refused_message_reaches_the_sender_as_a_notice(deployment):
    """The core claim: hub acked it, gate refused it, and the sender is told anyway."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    context = "c-thread-50"

    rewrite(root, "muse", block=[f"carl@{DOMAIN}"])
    apply_policy(muse, policy_path(root, "muse"))

    send(carl, muse.identity.agent_id, "are you there?", context=context, message_id="m-50")
    refused = muse.poll_once()
    assert refused["refused"] == 1, "the gate must refuse a blocked sender"
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
    assert notice["rule"] == "blocked"

    # The sender's own mailbox is clear: the notice was handled, not left to be re-offered.
    assert carl.client.fetch()["messages"] == []


def test_a_notice_is_not_a_message_in_a_thread(deployment):
    """It must not be queued, must not spend a reply expectation, and must not reach the inbox."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

    rewrite(root, "muse", block=[f"carl@{DOMAIN}"])
    apply_policy(muse, policy_path(root, "muse"))
    send(carl, muse.identity.agent_id, "one", context="c-quiet", message_id="m-quiet")
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

    rewrite(root, "muse", block=[f"carl@{DOMAIN}"])
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
    assert record["rule"] == "blocked"
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


def test_a_notice_flood_is_bounded(deployment):
    """A notice is handled before the gate, so it needs a bound of its own."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

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
