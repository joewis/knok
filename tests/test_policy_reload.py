"""A running bridge adopts a changed ``policy.json`` without a restart (#52).

The clock is the assertion, never a restart: each test edits the file under a bridge that is already
running, then polls it, and expects the *next* message to be decided by the file that is on disk now.
A run that passes because the bridge was bounced is a fail, so nothing here rebuilds a ``Bridge``.
"""

from __future__ import annotations

import json
import os

import pytest

from knok.bridge import Bridge, BridgeState, load_cards
from knok.policy import PolicyError

from test_phase2 import AGENTS, DOMAIN, deployment, send  # noqa: F401  (fixture reused by import)


def write_policy(path, **changes):
    """Rewrite the policy file in place, the way ``provision.py`` and an operator both do."""
    policy = json.loads(path.read_text())
    policy.update(changes)
    path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
    return policy


def allow_everyone_but(root, name, *excluded):
    path = root / "agents" / name / "policy.json"
    return write_policy(path, allow=[f"{other}@{DOMAIN}" for other in AGENTS
                                     if other != name and other not in excluded])


def test_revocation_takes_effect_on_the_next_message(deployment):
    """A peer removed from the allow-list is refused by a bridge that was never restarted."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

    # Muse is admitted to begin with: the old policy lets her through.
    send(carl, muse.identity.agent_id, "before the revocation", message_id="m-before")
    first = muse.poll_once()
    assert first["queued"] == 1, "the allow-listed sender must be delivered"
    assert muse.queue.get() is not None

    # The operator revokes carl mid-run. No restart, no signal — only the file changed.
    allow_everyone_but(root, "muse", "carl")

    send(carl, muse.identity.agent_id, "after the revocation", message_id="m-after")
    second = muse.poll_once()
    assert second["refused"] == 1, "the running policy must refuse a peer the file no longer allows"
    assert second["queued"] == 0
    assert muse.queue.get() is None, "a revoked peer must not reach the application"
    assert muse.client.fetch()["messages"] == [], "the refusal is still handled, so the hub is clear"


def test_admission_takes_effect_on_the_next_message(deployment):
    """The addition direction: a peer added mid-run is recognised instead of silently refused."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

    allow_everyone_but(root, "muse", "carl")
    send(carl, muse.identity.agent_id, "too early", message_id="m-early")
    assert muse.poll_once()["refused"] == 1, "not yet allowed: refused under the old policy"

    allow_everyone_but(root, "muse")
    send(carl, muse.identity.agent_id, "now allowed", message_id="m-now")
    counts = muse.poll_once()
    assert counts["queued"] == 1, "the added peer must be admitted without a restart"
    delivered = muse.queue.get()
    assert delivered["message"]["messageId"] == "m-now"


def test_a_block_lands_without_a_restart(deployment):
    """``block`` wins over ``allow`` (§9 order), and a new block is live on the next poll."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]

    send(carl, muse.identity.agent_id, "before the block", message_id="m-open")
    assert muse.poll_once()["queued"] == 1
    muse.queue.get()

    write_policy(root / "agents" / "muse" / "policy.json", block=[f"carl@{DOMAIN}"])
    send(carl, muse.identity.agent_id, "after the block", message_id="m-blocked")
    counts = muse.poll_once()
    assert counts["refused"] == 1
    assert muse.queue.get() is None


def test_a_broken_policy_keeps_the_policy_in_force(deployment, caplog):
    """Fail closed, loudly, and once: a typo must neither open the gate nor crash the bridge."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    path = root / "agents" / "muse" / "policy.json"

    path.write_text("{ this is not json ")
    with caplog.at_level("ERROR", logger="knok.bridge"):
        assert muse.reload_policy_if_changed() is False
    assert any("policy reload failed" in record.message for record in caplog.records)
    assert muse.policy.allow == frozenset(
        f"{other}@{DOMAIN}" for other in AGENTS if other != "muse"
    ), "the old policy must still be in force"

    # The bridge still works on the old policy: an allow-listed sender is still delivered.
    send(carl, muse.identity.agent_id, "still running", message_id="m-still")
    assert muse.poll_once()["queued"] == 1

    # And the broken file is not re-parsed (or re-logged) on every poll afterwards.
    caplog.clear()
    with caplog.at_level("ERROR", logger="knok.bridge"):
        muse.poll_once()
    assert not any("policy reload failed" in record.message for record in caplog.records)


def test_a_policy_for_another_agent_is_refused(deployment, caplog):
    """Swapping in the wrong agent's policy would gate one agent with another's allow-list."""
    hub, bridges, root = deployment
    muse = bridges["muse"]
    before = muse.policy
    write_policy(root / "agents" / "muse" / "policy.json", agent_id=f"carl@{DOMAIN}")
    with caplog.at_level("ERROR", logger="knok.bridge"):
        assert muse.reload_policy_if_changed() is False
    assert muse.policy == before
    assert any("policy reload refused" in record.message for record in caplog.records)


def test_reload_rebuilds_the_gate_but_not_the_stores(deployment):
    """``Threads``/``Rates``/``Contacts`` are DB-backed and must survive the policy that fed them."""
    hub, bridges, root = deployment
    muse = bridges["muse"]
    threads, rates, contacts, identity = muse.threads, muse.rates, muse.contacts, muse.identity
    queue = muse.queue

    allow_everyone_but(root, "muse", "carl")
    assert muse.reload_policy_if_changed() is True
    assert muse.gate.policy is muse.policy, "the rebuilt gate must decide on the new policy"
    assert muse.gate.threads is threads
    assert muse.gate.rates is rates
    assert muse.gate.contacts is contacts
    assert (muse.threads, muse.rates, muse.contacts, muse.queue, muse.identity) == (
        threads, rates, contacts, queue, identity
    )

    # A rewrite with identical content is not a reload: nothing to rebuild, nothing to log.
    assert muse.reload_policy_if_changed() is False


def test_a_deleted_policy_is_reported_and_the_old_one_stays(deployment, caplog):
    hub, bridges, root = deployment
    muse = bridges["muse"]
    path = root / "agents" / "muse" / "policy.json"
    os.unlink(path)
    with caplog.at_level("ERROR", logger="knok.bridge"):
        assert muse.reload_policy_if_changed() is False
    assert any("is gone or unreadable" in record.message for record in caplog.records)
    assert muse.policy.agent_id == muse.identity.agent_id


def test_load_is_still_strict_about_the_file(deployment):
    """The reload path must not have softened ``policy.load`` to make a bad edit survivable."""
    hub, bridges, root = deployment
    path = root / "agents" / "muse" / "policy.json"
    write_policy(path, unknown_key=True)
    with pytest.raises(PolicyError):
        from knok import policy as policy_mod

        policy_mod.load(path)
