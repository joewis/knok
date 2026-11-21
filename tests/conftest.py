import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from knok.identity import generate  # noqa: E402


def _stamp(delta: timedelta) -> str:
    """A wire timestamp relative to the wall clock, never a fixed date.

    The envelope fixture used to carry literal dates, so the whole suite turned
    red the moment the clock passed them; a test that fails because a day
    changed tells you nothing about the code.
    """
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def identity():
    return generate("carl", "bridge.example")


@pytest.fixture
def peer():
    return generate("muse", "bridge.example")


@pytest.fixture
def envelope_factory(identity, peer):
    def build(**overrides):
        envelope = {
            "envelopeVersion": 1,
            "seq": 0,
            "message": {
                "kind": "message",
                "messageId": "m-1",
                "contextId": "c-1",
                "role": "agent",
                "parts": [{"kind": "text", "text": "is §4 ready?"}],
            },
            "from": identity.agent_id,
            "to": [peer.agent_id],
            "sentAt": _stamp(timedelta(hours=-1)),
            "expiresAt": _stamp(timedelta(hours=23)),
            "turn": {"expectsReply": True, "closesThread": False},
        }
        envelope.update(overrides)
        return envelope

    return build
