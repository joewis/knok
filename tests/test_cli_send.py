"""Regression tests for the removed ``knok send --reply-to`` flag (issue #36).

``--reply-to`` inserted a ``replyTo`` field into the A2A ``Message`` dict, but
``replyTo`` is not an A2A v1.0 ``Message`` field, so ``validate_message`` (and
``sign``, via ``validate``) rejected every message built with the flag. The
flag could never work. The spec (§6) defines no ``replyTo``: a reply is a
``Message`` in the same ``contextId`` thread, which ``--context`` already
provides. The flag is gone; these tests pin that.
"""

import pytest

from knok.bridge import BridgeState
from knok.cli import main
from knok.message import MessageValidationError, validate_message


def _valid_message(**overrides):
    message = {
        "kind": "message",
        "messageId": "m-1",
        "contextId": "c-1",
        "role": "agent",
        "parts": [{"kind": "text", "text": "hello"}],
    }
    message.update(overrides)
    return message


def test_send_builds_message_without_reply_to(monkeypatch, tmp_path, identity):
    """`cmd_send` must emit a strict-A2A message: no `replyTo`, valid as built."""
    state = BridgeState(
        agent_id=identity.agent_id,
        directory=tmp_path,
        hub_url="http://127.0.0.1:1",
        registry={"muse@bridge.example": {}},
    )
    monkeypatch.setattr("knok.cli._state_from_env", lambda: (state, identity))

    captured = []

    class CapturingClient:
        def __init__(self, hub_url, identity):
            pass

        def deposit(self, envelope):
            captured.append(envelope)
            return {}

    monkeypatch.setattr("knok.cli.HubClient", CapturingClient)

    assert (
        main(
            [
                "send",
                "--to", "muse@bridge.example",
                "--text", "hello",
                "--context", "c-9",
            ]
        )
        == 0
    )
    assert len(captured) == 1
    message = captured[0]["message"]
    assert "replyTo" not in message
    assert message["contextId"] == "c-9"
    # The envelope as built must pass the strict A2A validator.
    assert validate_message(message)["messageId"] == message["messageId"]


def test_validate_message_rejects_reply_to():
    """A `replyTo` field is still a protocol error, not a tolerated extra."""
    with pytest.raises(MessageValidationError, match="replyTo"):
        validate_message(_valid_message(replyTo="m-0"))


def test_send_parser_rejects_reply_to():
    """The removed flag is gone from the parser, not just ignored."""
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "send",
                "--to", "muse@bridge.example",
                "--text", "hello",
                "--reply-to", "m-1",
            ]
        )
    assert excinfo.value.code == 2


def test_a_follow_up_in_a_thread_takes_the_next_seq(monkeypatch, tmp_path, identity):
    """The default was a flat 0, so the second message in a thread was silently refused (#142).

    Two sends in one context, no ``--seq``: the receiver orders by seq per thread and per sender,
    so the first is 0 and the second must be 1, or the follow-up question arrives at a spent
    position and the queue answers "conflict" — which is what happened for real.
    """
    state = BridgeState(
        agent_id=identity.agent_id,
        directory=tmp_path,
        hub_url="http://127.0.0.1:1",
        registry={"muse@bridge.example": {}},
    )
    monkeypatch.setattr("knok.cli._state_from_env", lambda: (state, identity))
    sent: list[dict] = []

    class CapturingClient:
        def __init__(self, hub_url, identity):
            pass

        def deposit(self, envelope):
            sent.append(envelope)
            return {}

    monkeypatch.setattr("knok.cli.HubClient", CapturingClient)

    for text in ("first", "follow-up", "third"):
        assert main(["send", "--to", "muse@bridge.example", "--text", text,
                     "--context", "c-thread"]) == 0

    assert [envelope["seq"] for envelope in sent] == [0, 1, 2]
    # A different thread starts at 0 again: seq is per (context, sender, recipient).
    assert main(["send", "--to", "muse@bridge.example", "--text", "other thread",
                 "--context", "c-other"]) == 0
    assert sent[-1]["seq"] == 0


def test_an_explicit_seq_still_wins(monkeypatch, tmp_path, identity):
    """The auto default must not override a caller that knows the position — retries rely on it."""
    state = BridgeState(
        agent_id=identity.agent_id,
        directory=tmp_path,
        hub_url="http://127.0.0.1:1",
        registry={"muse@bridge.example": {}},
    )
    monkeypatch.setattr("knok.cli._state_from_env", lambda: (state, identity))
    sent: list[dict] = []

    class CapturingClient:
        def __init__(self, hub_url, identity):
            pass

        def deposit(self, envelope):
            sent.append(envelope)
            return {}

    monkeypatch.setattr("knok.cli.HubClient", CapturingClient)

    for seq in (0, 7):
        assert main(["send", "--to", "muse@bridge.example", "--text", f"s{seq}",
                     "--context", "c-thread", "--seq", str(seq)]) == 0
    assert [envelope["seq"] for envelope in sent] == [0, 7]
