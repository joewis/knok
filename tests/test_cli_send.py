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
