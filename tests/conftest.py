import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from knok.identity import generate  # noqa: E402


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
            "sentAt": "2026-11-18T05:00:00Z",
            "expiresAt": "2026-11-21T05:00:00Z",
            "turn": {"expectsReply": True, "closesThread": False},
        }
        envelope.update(overrides)
        return envelope

    return build
