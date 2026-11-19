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
