"""`knok recv` — the one-shot pull, and the at-most-once contract it claims.

recv_once prints before it acks, so the caller's stdout is the durable sink. Every test here runs
against a real hub over loopback: "printed, then acked" is only worth asserting if the ack actually
deletes, and if a failed print actually leaves the mail in the mailbox.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "hub"))

import hub_helpers as helpers  # noqa: E402
from knok.bridge import BridgeState, load_cards  # noqa: E402
from knok.cli import main  # noqa: E402
from knok.recv import recv_once  # noqa: E402


@pytest.fixture
def agent_state(tmp_path):
    """A hub, plus muse's local state: her key on disk and the signed registry beside it."""
    ns = helpers.make_hub(tmp_path)
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir()
    for agent_id, card in ns.cards.items():
        (registry_dir / f"{agent_id}.json").write_text(json.dumps(card))
    state_dir = tmp_path / "muse"
    ns.muse_id.save(state_dir / "identity.key")
    state = BridgeState(
        agent_id=ns.muse_id.agent_id,
        directory=state_dir,
        hub_url=ns.url,
        registry=load_cards(registry_dir),
    )
    yield ns, state
    helpers.close_hub(ns)


def deposit(ns, *, text, seq=0, context="c-1"):
    envelope = helpers.build_envelope(
        ns.carl_id, ns.muse_id.agent_id, text=text, seq=seq, context_id=context
    )
    status, body, _ = helpers.deposit(ns.url, envelope)
    assert status == 202
    return envelope


def test_recv_acks_a_hub_expired_frame_so_it_stops_reprinting(agent_state, capsys):
    """A frame is mail too: printed once, then acked, or it re-prints on every recv.

    An envelope that is already past ``expiresAt`` at deposit is never delivered; the hub answers
    the *sender* with a signed ``expired`` frame instead, and that frame is a bare transport frame
    — ``kind`` and ``messageId`` at the top level, no ``message`` wrapper. Its id is the only one
    an ack can use, so a recv that only looks inside ``message`` never acks it.
    """
    ns, state = agent_state
    moment = helpers.now_dt()
    # Signed while it was still live, past its expiry by the time the hub reads it.
    dead = helpers.build_envelope(
        ns.muse_id, ns.carl_id.agent_id, text="too late",
        sent_at=helpers.iso(moment - timedelta(minutes=10)),
        expires_at=helpers.iso(moment - timedelta(minutes=1)),
        sign_now=moment - timedelta(minutes=5),
    )
    status, _body, _ = helpers.deposit(ns.url, dead)
    assert status == 202

    assert recv_once(state, ns.muse_id) == 1

    printed = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [frame["kind"] for frame in printed] == ["expired"]
    assert printed[0]["messageId"] == dead["message"]["messageId"]

    # Read once, gone from the hub: a second pass prints nothing and has nothing to ack.
    assert recv_once(state, ns.muse_id) == 0
    assert capsys.readouterr().out == ""

    status, page = helpers.fetch_as(ns.url, ns.muse_id)
    assert status == 200
    assert page["messages"] == []


def test_recv_prints_each_envelope_then_acks(agent_state, capsys):
    """One JSON line per envelope, oldest first; the ack then empties the mailbox."""
    ns, state = agent_state
    first = deposit(ns, text="one")
    second = deposit(ns, text="two", seq=1)

    assert recv_once(state, ns.muse_id) == 2

    lines = capsys.readouterr().out.splitlines()
    assert [json.loads(line) for line in lines] == [first, second]

    status, page = helpers.fetch_as(ns.url, ns.muse_id)
    assert status == 200
    assert page["messages"] == []

    # The batch is gone, so a second run has nothing to print and must not ack anything.
    assert recv_once(state, ns.muse_id) == 0
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("failure", ["write", "flush"])
def test_a_print_that_fails_does_not_ack(agent_state, monkeypatch, failure):
    """No ack until the output has landed: a broken stdout leaves the mail at the hub."""
    ns, state = agent_state
    deposit(ns, text="one")

    class BrokenStdout:
        def write(self, _text):
            if failure == "write":
                raise OSError("stdout is gone")

        def flush(self):
            if failure == "flush":
                raise OSError("stdout is gone")

    monkeypatch.setattr(sys, "stdout", BrokenStdout())

    with pytest.raises(OSError):
        recv_once(state, ns.muse_id)

    status, page = helpers.fetch_as(ns.url, ns.muse_id)
    assert status == 200
    assert len(page["messages"]) == 1


def test_cli_recv_passes_the_limit(monkeypatch):
    """`knok recv --limit N` reaches recv_once; the default is 20."""
    limits = []

    def fake_recv_once(state, identity, *, limit):
        limits.append(limit)
        return 0

    monkeypatch.setattr("knok.cli._state_from_env", lambda: (object(), object()))
    monkeypatch.setattr("knok.cli.recv_once", fake_recv_once)

    assert main(["recv"]) == 0
    assert main(["recv", "--limit", "3"]) == 0
    assert limits == [20, 3]


def _write_policy(state_dir, agent_id, *, allow=(), block=()):
    """A closed private policy for the agent, the way ``provision.py`` writes one."""
    policy = {
        "agent_id": agent_id,
        "contact_policy": "closed",
        "deployment": "private",
        "allow": list(allow),
        "block": list(block),
        "limits": {},
    }
    (state_dir / "policy.json").write_text(json.dumps(policy))
    return policy


def test_recv_does_not_print_mail_from_a_blocked_sender(agent_state, capsys):
    """Scenario 11 (#51): a blocked sender's queued mail never reaches recv stdout.

    The mail was queued before the block, so the hub accepted it; the receiver's gate is the
    only thing standing between it and stdout. The refusal is handled, so the hub is clear.
    """
    ns, state = agent_state
    _write_policy(
        state.directory, ns.muse_id.agent_id,
        allow=[ns.carl_id.agent_id], block=[ns.mallory_id.agent_id],
    )
    blocked = helpers.build_envelope(
        ns.mallory_id, ns.muse_id.agent_id, text="from mallory", context_id="c-blocked"
    )
    status, _, _ = helpers.deposit(ns.url, blocked)
    assert status == 202
    allowed = deposit(ns, text="from carl")

    assert recv_once(state, ns.muse_id) == 1

    lines = capsys.readouterr().out.splitlines()
    assert [json.loads(line) for line in lines] == [allowed]

    status, page = helpers.fetch_as(ns.url, ns.muse_id)
    assert status == 200
    assert page["messages"] == []


def test_recv_does_not_print_mail_from_a_sender_the_policy_does_not_admit(agent_state, capsys):
    """Closed by default: a sender in neither the allow-list nor the contacts is refused."""
    ns, state = agent_state
    _write_policy(
        state.directory, ns.muse_id.agent_id, allow=[ns.carl_id.agent_id]
    )
    stranger = helpers.build_envelope(
        ns.mallory_id, ns.muse_id.agent_id, text="from mallory", context_id="c-stranger"
    )
    status, _, _ = helpers.deposit(ns.url, stranger)
    assert status == 202
    allowed = deposit(ns, text="from carl")

    assert recv_once(state, ns.muse_id) == 1

    lines = capsys.readouterr().out.splitlines()
    assert [json.loads(line) for line in lines] == [allowed]

    status, page = helpers.fetch_as(ns.url, ns.muse_id)
    assert status == 200
    assert page["messages"] == []


def test_recv_does_not_print_mail_from_a_revoked_sender(tmp_path, capsys):
    """Scenario 11, the registry half (#51): a peer whose card was removed is refused.

    Muse's side holds no policy, so the pinned registry is the allow-list: removing a card
    revokes the peer for recv, and mail queued before the removal is refused, not printed.
    The hub still accepts the deposit — it has its own registry — so the receiver's gate is
    the only thing standing between the mail and stdout.
    """
    ns = helpers.make_hub(tmp_path)
    try:
        registry_dir = tmp_path / "registry"
        registry_dir.mkdir()
        # Mallory's card is gone: the operator revoked her by removing it.
        for agent_id in (ns.carl_id.agent_id, ns.muse_id.agent_id):
            (registry_dir / f"{agent_id}.json").write_text(json.dumps(ns.cards[agent_id]))
        state_dir = tmp_path / "muse"
        ns.muse_id.save(state_dir / "identity.key")
        state = BridgeState(
            agent_id=ns.muse_id.agent_id,
            directory=state_dir,
            hub_url=ns.url,
            registry=load_cards(registry_dir),
        )
        revoked = helpers.build_envelope(
            ns.mallory_id, ns.muse_id.agent_id, text="from mallory", context_id="c-revoked"
        )
        status, _, _ = helpers.deposit(ns.url, revoked)
        assert status == 202
        allowed = helpers.build_envelope(
            ns.carl_id, ns.muse_id.agent_id, text="from carl", context_id="c-ok"
        )
        status, _, _ = helpers.deposit(ns.url, allowed)
        assert status == 202

        assert recv_once(state, ns.muse_id) == 1

        lines = capsys.readouterr().out.splitlines()
        assert [json.loads(line) for line in lines] == [allowed]

        status, page = helpers.fetch_as(ns.url, ns.muse_id)
        assert status == 200
        assert page["messages"] == []
    finally:
        helpers.close_hub(ns)


def _closed_policy(state, allow=()):
    """A policy file that admits nobody we did not name. Returns its path."""
    path = state.directory / "policy.json"
    path.write_text(json.dumps({
        "agent_id": state.agent_id,
        "contact_policy": "closed",
        "deployment": "private",
        "allow": list(allow),
        "block": [],
        "limits": {},
    }))
    return path


def test_a_notice_is_printed_even_when_its_sender_is_not_admitted(agent_state, capsys):
    """"A notice is a statement about our own message, not mail to be gated (#51).

    ``bridge._handle`` checks ``message.metadata[knok.notice]`` before the gate "so it can never
    enter a thread or a gate decision"; recv must do the same or a recv-only agent never learns
    that what it sent was refused or expired.
    """
    ns, state = agent_state
    _closed_policy(state)  # carl is not admitted
    # Built and signed with the metadata in place: adding it after signing invalidates the
    # signature, and the hub would answer 403 for a reason that has nothing to do with the test.
    unsigned = {
        "envelopeVersion": 1,
        "seq": 0,
        "message": {
            "kind": "message",
            "messageId": helpers.new_message_id(),
            "contextId": "c-notice",
            "role": "agent",
            "parts": [{"kind": "text", "text": "refused: policy"}],
            "metadata": {"knok.notice": {"reason": "policy"}},
        },
        "from": ns.carl_id.agent_id,
        "to": [ns.muse_id.agent_id],
        "sentAt": helpers.iso(helpers.now_dt() - timedelta(minutes=1)),
        "expiresAt": helpers.iso(helpers.now_dt() + timedelta(hours=72)),
        "turn": {"expectsReply": False, "closesThread": False},
    }
    envelope = helpers.sign(unsigned, ns.carl_id)
    status, _body, _ = helpers.deposit(ns.url, envelope)
    assert status == 202

    assert recv_once(state, ns.muse_id) == 1
    printed = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert printed[0]["message"]["metadata"]["knok.notice"]["reason"] == "policy"

    # And it is acked like any handled item, so it does not re-print.
    status, page = helpers.fetch_as(ns.url, ns.muse_id)
    assert page["messages"] == []


def test_a_refused_message_prints_the_uniform_reason_and_not_the_internal_rule(
    agent_state, capsys
):
    """``gate.rule`` is an internal category; ``blocked`` is never quoted anywhere (#51)."""
    ns, state = agent_state
    _closed_policy(state)
    deposit(ns, text="let me in")

    assert recv_once(state, ns.muse_id) == 0
    err = capsys.readouterr().err
    assert "gate refused" in err
    # The refusal string is shared by every refusal class, so it must not name the rule.
    assert "policy" not in err and "blocked" not in err


def test_a_sealed_envelope_is_left_at_the_hub_rather_than_acked_away(
    agent_state, capsys, monkeypatch
):
    """recv cannot read form 2, so it must not destroy it either (#51, #70).

    The hub refuses to deposit a sealed envelope today, which is the only reason this cannot be
    exercised through it. The guard matters for the day that changes: an ack is deletion.
    """
    ns, state = agent_state
    sealed = {
        "envelopeVersion": 1,
        "seq": 0,
        "from": ns.carl_id.agent_id,
        "to": [ns.muse_id.agent_id],
        "sentAt": helpers.iso(helpers.now_dt()),
        "expiresAt": helpers.iso(helpers.now_dt() + timedelta(hours=1)),
        "messageId": "m-sealed-1",
        "sealed": {"hpke": {"enc": "x", "ciphertext": "y"}, "recipientKeyId": "z"},
    }
    acked = []

    class FakeBody:
        @staticmethod
        def get(key, default=None):
            return [sealed] if key == "messages" else default

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def fetch(self, limit=None):
            return FakeBody()

        def ack(self, ids):
            acked.extend(ids)

    monkeypatch.setattr("knok.recv.HubClient", FakeClient)

    assert recv_once(state, ns.muse_id) == 0
    assert capsys.readouterr().out == ""
    assert acked == [], "a sealed envelope was acked: that deletes mail recv cannot read"


def test_recv_acks_a_delivered_frame_so_the_sender_is_told_once(agent_state, capsys):
    """A ``delivered`` frame is a transport frame, not a sealed envelope (#144).

    Since 0.4 the hub mints one into the sender's mailbox when the recipient's bridge acks, so a
    recv-only agent learns its message landed. The reader recognised a frame by the absence of a
    ``message`` key, which is also how a sealed form-2 envelope looks, so the frame fell into the
    "leave it at the hub" branch: never printed, never acked, re-offered on every recv forever.
    """
    ns, state = agent_state
    envelope = deposit(ns, text="did you get this?", seq=0, context="c-delivered")
    message_id = envelope["message"]["messageId"]

    # The recipient acks it, which is what queues the hub's frame back into our mailbox.
    from knok.hubclient import HubClient

    HubClient(ns.url, ns.muse_id).ack([message_id])

    assert recv_once(state, ns.carl_id) == 1
    printed = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [frame["kind"] for frame in printed] == ["delivered"]
    assert printed[0]["messageId"] == message_id

    # Read once, acked once: the mailbox is empty on the next pass.
    assert recv_once(state, ns.carl_id) == 0
